package ru.nsu.ccfit.zdarovamujiki;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.channels.spi.SelectorProvider;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.logging.Level;

import lombok.extern.java.Log;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import static ru.nsu.ccfit.zdarovamujiki.Proxy.Attachment.State.*;

@Log
public class Proxy {
    private static final int BUFFER_SIZE = 8192;
    private static final byte SOCKS_VERSION = 5;
    private static final byte ADDRESS_TYPE_IP_V4 = 1;
    private static final byte ADDRESS_TYPE_DOMAIN_NAME = 3;
    private static final byte ADDRESS_TYPE_IP_V6 = 4;
    private static final String HOST = "localhost";
    private static final ByteBuffer OK_RESPONSE = ByteBuffer.wrap(new byte[]{5, 0});

    private SelectionKey resolverKey;
    private InetSocketAddress resolverAddress;
    private final HashMap<String, LinkedList<SelectionKey>> toResolve = new HashMap<>();

    static class Attachment {
        ByteBuffer in = ByteBuffer.allocate(BUFFER_SIZE);
        ByteBuffer out = ByteBuffer.allocate(BUFFER_SIZE);
        SelectionKey peer;

        public enum State {SERVER, GET_VERSION, SEND_ACCEPT, CONNECT_TO_SERVER, READY}
        State state = GET_VERSION;
    }
    public void start(int port) {
        try {
            Selector selector = SelectorProvider.provider().openSelector();
            DatagramChannel resolverChannel = DatagramChannel.open();
            resolverChannel.configureBlocking(false);
            resolverAddress = ResolverConfig.getCurrentConfig().servers().get(0);
            resolverKey = resolverChannel.register(selector, SelectionKey.OP_READ);
            resolverKey.attach(new Attachment());

            ServerSocketChannel serverChannel = ServerSocketChannel.open();
            serverChannel.configureBlocking(false);
            serverChannel.socket().bind(new InetSocketAddress(HOST, port));
            serverChannel.register(selector, serverChannel.validOps());
            while (selector.select() > -1) {
                Iterator<SelectionKey> iterator = selector.selectedKeys().iterator();
                while (iterator.hasNext()) {
                    SelectionKey key = iterator.next();
                    iterator.remove();
                    if (key.isValid()) {
                        try {
                            if (key.isAcceptable()) {
                                accept(key);
                            } else if (key.isConnectable()) {
                                connect(key);
                            } else if (key.isReadable()) {
                                read(key);
                            } else if (key.isWritable()) {
                                write(key);
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                            close(key);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.log(Level.WARNING, "Error starting");
        }
    }

    private void accept(SelectionKey key) throws IOException {
        SocketChannel newChannel = ((ServerSocketChannel) key.channel()).accept();
        log.log(Level.FINE, "accepting " + newChannel);
        newChannel.configureBlocking(false);
        newChannel.register(key.selector(), SelectionKey.OP_READ);
    }

    private void read(SelectionKey key) throws IOException {
        Attachment attachment = (Attachment) key.attachment();
        if (attachment == null) {
            key.attach(attachment = new Attachment());
        }

        attachment.in.clear();
        if (key == resolverKey) {
            DatagramChannel resolverChannel = (DatagramChannel) resolverKey.channel();
            resolverChannel.receive(attachment.in);
            Message message = new Message(attachment.in.array());
            String address = message.getSection(Section.ANSWER).get(0).rdataToString();
            InetAddress inetAddress = InetAddress.getByName(address);

            String hostname = message.getQuestion().getName().toString();
            LinkedList<SelectionKey> clientKeys = toResolve.get(hostname);
            if (clientKeys == null) {
                return;
            }
            for (SelectionKey clientKey : clientKeys) {
                if (!clientKey.isValid()) {
                    continue;
                }
                Attachment clientAttachment = (Attachment) clientKey.attachment();
                prepareToConnect(clientKey, inetAddress, getPort(clientAttachment.in.array()));
            }
            toResolve.remove(hostname);
            return;
        }
        SocketChannel channel = (SocketChannel) key.channel();
        if (channel.read(attachment.in) < 1) {
            close(key);
            return;
        }
        byte[] buffer = attachment.in.array();
        if (attachment.state == GET_VERSION) {
            if (buffer[0] != SOCKS_VERSION) {
                log.log(Level.WARNING, "Only SOCKS5 supported");
                close(key);
                return;
            }
            key.interestOpsOr(SelectionKey.OP_WRITE);
            attachment.out = OK_RESPONSE;
            attachment.state = SEND_ACCEPT;
            return;
        } else if (attachment.state == CONNECT_TO_SERVER) {
            switch (buffer[3]) {
                case ADDRESS_TYPE_IP_V4 -> {
                    byte[] address = new byte[]{buffer[4], buffer[5], buffer[6], buffer[7]};
                    prepareToConnect(key, InetAddress.getByAddress(address), getPort(buffer));
                }
                case ADDRESS_TYPE_DOMAIN_NAME -> {
                    int length = buffer[4];
                    byte[] address = new byte[length];
                    System.arraycopy(buffer, 5, address, 0, length);
                    String domainName = new String(address) + ".";
                    if (!toResolve.containsKey(domainName)) {
                        toResolve.put(domainName, new LinkedList<>());
                    }
                    toResolve.get(domainName).add(key);
                    Message message = createMessage(domainName);

                    DatagramChannel resolverChannel = (DatagramChannel) resolverKey.channel();
                    resolverChannel.send(ByteBuffer.wrap(message.toWire()), resolverAddress);
                    return;
                }
                case ADDRESS_TYPE_IP_V6 -> {
                    log.log(Level.WARNING, "IP V6 not supported");
                    close(key);
                    return;
                }
            }
        }
        if (attachment.peer != null) {
            attachment.peer.interestOpsOr(SelectionKey.OP_WRITE);
        }
        key.interestOpsAnd(~SelectionKey.OP_READ);
        attachment.in.flip();
    }

    private void write(SelectionKey key) throws IOException {
        SocketChannel channel = ((SocketChannel) key.channel());
        Attachment attachment = ((Attachment) key.attachment());
        if (channel.write(attachment.out) == -1) {
            close(key);
            return;
        }
        if (attachment.peer != null) {
            attachment.peer.interestOpsOr(SelectionKey.OP_READ);
        } else {
            attachment.state = CONNECT_TO_SERVER;
        }
        key.interestOpsAnd(~SelectionKey.OP_WRITE);
        attachment.out.clear();
    }

    private void connect(SelectionKey serverKey) throws IOException {
        SocketChannel serverChannel = ((SocketChannel) serverKey.channel());
        Attachment serverAttachment = ((Attachment) serverKey.attachment());
        log.log(Level.FINE, "connecting " + serverChannel);
        serverChannel.finishConnect();

        int port = serverChannel.socket().getLocalPort();
        byte[] reply = new byte[10];
        reply[0] = SOCKS_VERSION;
        reply[3] = ADDRESS_TYPE_IP_V4;
        reply[8] = (byte) ((port & 0xFF00) >> 8);
        reply[9] = (byte) (port & 0x00FF);

        Attachment clientAttachment = (Attachment) serverAttachment.peer.attachment();
        serverAttachment.in.put(reply).flip();
        serverAttachment.out = clientAttachment.in;
        clientAttachment.out = serverAttachment.in;
        serverAttachment.peer.interestOps(SelectionKey.OP_WRITE | SelectionKey.OP_READ);
        serverKey.interestOps(0);

        clientAttachment.state = READY;
    }

    private void close(SelectionKey key) throws IOException {
        log.log(Level.FINE, String.valueOf(key.channel()));
        key.cancel();
        key.channel().close();
        SelectionKey peerKey = ((Attachment) key.attachment()).peer;
        if (peerKey != null) {
            Attachment peerAttachment = (Attachment) peerKey.attachment();
            peerAttachment.peer = null;
            if ((peerKey.interestOps() & SelectionKey.OP_WRITE) == 0) {
                peerAttachment.out.flip();
            }
            peerKey.interestOps(SelectionKey.OP_WRITE);
        }
    }

    private int getPort(byte[] buffer) {
        int addressLength = 4;
        if (buffer[3] == ADDRESS_TYPE_DOMAIN_NAME) {
            addressLength = buffer[4] + 1;
        }
        return (((0xFF & buffer[4 + addressLength]) << 8) + (0xFF & buffer[5 + addressLength]));
    }

    private void prepareToConnect(SelectionKey clientKey, InetAddress address, int port) throws IOException {
        SocketChannel serverChannel = SocketChannel.open();
        serverChannel.configureBlocking(false);
        serverChannel.connect(new InetSocketAddress(address, port));
        SelectionKey serverKey = serverChannel.register(clientKey.selector(), SelectionKey.OP_CONNECT);
        clientKey.interestOps(0);

        Attachment clientAttachment = (Attachment) clientKey.attachment();
        Attachment serverAttachment = new Attachment();
        clientAttachment.peer = serverKey;
        serverAttachment.peer = clientKey;
        serverAttachment.state = SERVER;
        serverKey.attach(serverAttachment);
    }

    private Message createMessage(String domainName) throws TextParseException {
        Message message = new Message();
        Header header = new Header();
        header.setFlag(Flags.RD);
        header.setOpcode(0);
        message.setHeader(header);

        Record record = Record.newRecord(new Name(domainName), Type.A, DClass.IN);
        message.addRecord(record, Section.QUESTION);
        return message;
    }
}
