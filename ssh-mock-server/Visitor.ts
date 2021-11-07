import net = require("net");
import util = require("util");
import crypto = require("crypto");
import { stringify } from "querystring";
import { States } from './States';
import { State } from './State';
import { SshBufferReader } from './SshBufferReader'
import { AlgorithmNegotiation } from './AlgorithmNegotiation'
import { KeyExchange } from './KeyExchange'
import { ServerConfig } from './ServerConfig'
import { Util } from './Util'
import { BufferWriter } from "./BufferWriter";
import { DiffieHellmanFactory } from "./DiffieHellmanFactory"

export class Visitor {
    // member variables
    private socket: net.Socket;
    private state: State;
    private config: ServerConfig;
    constructor(s: net.Socket, c: ServerConfig) {
        this.socket = s;
        this.config = c;

        // build state machine
        this.state = this.buildStateMachine();

        // bind events
        this.socket.on("close", this.onClose.bind(this));
        this.socket.on("connect", this.onConnect.bind(this));
        this.socket.on("data", this.onData.bind(this));
        this.socket.on("drain", this.onDrain.bind(this));
        this.socket.on("end", this.onEnd.bind(this));
        this.socket.on("error", this.onError.bind(this));
        this.socket.on("lookup", this.onLookup.bind(this));
        this.socket.on("ready", this.onReady.bind(this));
        this.socket.on("timeout", this.onTimeout.bind(this));

        // send protocol version
        // put in into config
    }

    // Emitted once the socket is fully closed. The argument hadError is a boolean which says if the socket was closed due to a transmission error.
    private onClose(hadError: boolean): void {
        console.log("visitor " + this.socket.remoteAddress + " closed");
    }

    // Emitted when a socket connection is successfully established. See net.createConnection().
    private onConnect(): void {
        console.log("Visitor.onConnect: " + this.socket.remoteAddress);
        this.state = this.state.getNextState();
    }

    // Emitted when data is received. The argument data will be a Buffer or String. Encoding of data is set by socket.setEncoding().
    private onData(data: any): void {
        if(data instanceof Buffer) {
            let b: Buffer = data;
            console.log("Visitor.onData");
            let s = this.state.currentState();
            // if we are still on init -> move next
            if(s == States.init) {
                this.state = this.state.getNextState();
                s = this.state.currentState();
            }
            console.log("current state: " + s);
            switch(s) {
                case States.read_ssh_version:
                    let sshString = data.toString('utf8');
                    if(sshString.startsWith('SSH-2.0')) {
                        console.log('SSH2.0 ok');
                        this.state = this.state.getNextState();
                        // send ssh version to visitor
                        this.sendString("SSH-2.0-ssh-mock-server\r\n");
                    } else {
                        console.log("wrong ssh version: " + sshString);
                        // close connection to visitor
                        // TODO: SSH_MSG_DISCONNECT
                        this.socket.end();
                        this.socket.destroy();
                    }
                    break;
                case States.read_keys:
                    this.processReadKeys(data);
                    break;
                case States.key_exchage:
                    this.processKeyExchange(data);
                    // Util.OutputArrayAsPairs("Visitor.onData key_exchage", data);
                    // TODO: read key as length + key SSH_MSG_KEXDH_INIT
                    // TODO: send key SSH_MSG_KEXDH_REPLY
                    break;
                default:
                    console.log("Visitor.onData -> default -> data: " + data);
                    break;
            }            
        }
    }
    private processReadKeys(data: Buffer) : void {
        let bufferReader = new SshBufferReader(data);
        let algorithmNegotiation = new AlgorithmNegotiation(bufferReader.getPayload())
        if(algorithmNegotiation.HasError() == false) {
            // TODO check kex_algorithms
            let algorithms = algorithmNegotiation.GetKexAlgorithmsList();
            Util.OutputArray("Visitor.onData LIST kex algorithms", algorithms);
            // TODO check server_host_key_algorithms
            algorithms = algorithmNegotiation.GetServerHostKeyAlgorithms()
            Util.OutputArray("Visitor.onData LIST server host key algorithms", algorithms);
            // TODO check encryption_algorithms_client_to_server
            algorithms = algorithmNegotiation.GetEncryptionAlgorithmsClientToServer();
            Util.OutputArray("Visitor.onData LIST encryption_algorithms_client_to_server", algorithms);
            // TODO check encryption_algorithms_server_to_client
            algorithms = algorithmNegotiation.GetEncryptionAlgorithmsServerToClient();
            Util.OutputArray("Visitor.onData LIST encryption_algorithms_server_to_client", algorithms);
            // TODO check mac_algorithms_client_to_server
            algorithms = algorithmNegotiation.GetMacAlgorithmsClientToServer();
            Util.OutputArray("Visitor.onData LIST mac_algorithms_client_to_server", algorithms);
            // TODO check mac_algorithms_server_to_client
            algorithms = algorithmNegotiation.GetMacAlgorithmsServerToClient();
            Util.OutputArray("Visitor.onData LIST mac_algorithms_server_to_client", algorithms);
            // TODO check compression_algorithms_client_to_server
            algorithms = algorithmNegotiation.GetCompressionAlgorithmsClientToServer();
            Util.OutputArray("Visitor.onData LIST compression_algorithms_client_to_server", algorithms);
            // TODO check compression_algorithms_server_to_client
            algorithms = algorithmNegotiation.GetCompressionAlgorithmsServerToClient();
            Util.OutputArray("Visitor.onData LIST compression_algorithms_server_to_client", algorithms);
            // TODO check languages_client_to_server
            algorithms = algorithmNegotiation.GetLanguagesClientToServer();
            Util.OutputArray("Visitor.onData LIST languages_client_to_server", algorithms);
            // TODO check languages_server_to_client
            algorithms = algorithmNegotiation.GetLanguagesServerToClient();
            Util.OutputArray("Visitor.onData LIST languages_server_to_client", algorithms);
            // SEND KEX TO VISITOR
            this.sendKex();
        }
        this.state = this.state.getNextState();
    }
    private processKeyExchange(data: Buffer) : void {
        let bufferReader = new SshBufferReader(data);
        let keyExchange = new KeyExchange(bufferReader.getPayload())
        // TODO: now its only one, could be an array later
        let dh = DiffieHellmanFactory.GetDiffieHellman(this.config.kex_algorithms);
        dh.generateKeys();
        const sharedSecret = dh.computeSecret(keyExchange.getKey());
        const serverKeyExchange = dh.getPublicKey();
        // ed25519
        const keypair = crypto.generateKeyPairSync('ed25519', { privateKeyEncoding: { format: 'pem', type: 'pkcs8' }, publicKeyEncoding: { format: 'pem', type: 'spki' } });
        const hostKey = keypair.publicKey;
        const exchangeHash = computeExchangeHash();
    }

    private computeExchangeHash() : Buffer {
        let writer = new BufferWriter();
        // protocol version exchange
        writer.appendBuffer
        // kex init client server
        // kex init server client
        // host key and certificates
        // client exchange value
        // server exchage value
        // shared secret
    }

    // Emitted when the write buffer becomes empty. Can be used to throttle uploads.
    private onDrain(): void {
        console.log("Visitor.onDrain");
    }

    // Emitted when the other end of the socket signals the end of transmission, thus ending the readable side of the socket.
    private onEnd(): void {
        console.log("Visitor.onEnd");
    }

    // Emitted when an error occurs. The 'close' event will be called directly following this event.
    private onError(e: Error): void {
        console.log("Visitor.onError");
        console.log(e.name);
        console.log(e.message);
        console.log(e.stack);
    }

    // Emitted after resolving the host name but before connecting. Not applicable to Unix sockets.
    private onLookup(e: Error, addr: string, family: string, host: string): void {
        console.log("Visitor.onLookup");
        console.log("error: " + e.name);
        console.log("address: " + addr);
        console.log("family: " + family);
        console.log("host: " + host);
    }

    // Emitted when a socket is ready to be used.
    private onReady(): void {
        console.log("Visitor.onReady");
    }

    // Emitted if the socket times out from inactivity. This is only to notify that the socket has been idle. The user must manually close the connection.
    private onTimeout(): void {
        console.log("Visitor.onTimeout");
    }
    
    public isConnected(): boolean {
        // TODO: ???
        if(this.socket != null) {
            return true;
        }
        return false;
    }

    public sendString(message: string): void {
        // rewrite this one
        if (!this.isConnected()) {
            return;
        }

        this.socket.write(message);
    }

    public sendKex() {
        // TODO: implement
        let algorithmNegotiation =  new AlgorithmNegotiation();
        // byte         SSH_MSG_KEXINIT
        // byte[16]     cookie (random bytes)
        algorithmNegotiation.setCookie(crypto.randomBytes(16));
        // name-list    kex_algorithms
        algorithmNegotiation.setKexAlgorithms(Buffer.from(this.config.kex_algorithms));
        // name-list    server_host_key_algorithms
        algorithmNegotiation.setServerHostKeyAlgorithms(Buffer.from(this.config.server_host_key_algorithms));
        // name-list    encryption_algorithms_client_to_server
        algorithmNegotiation.setEncryptionAlgorithmsClientToServer(Buffer.from(this.config.encryption_algorithms_client_to_server));
        // name-list    encryption_algorithms_server_to_client
        algorithmNegotiation.setEncryptionAlgorithmsServerToClient(Buffer.from(this.config.encryption_algorithms_server_to_client));
        // name-list    mac_algorithms_client_to_server
        algorithmNegotiation.setMacAlgorithmsClientToServer(Buffer.from(this.config.mac_algorithms_client_to_server));
        // name-list    mac_algorithms_server_to_client
        algorithmNegotiation.setMacAlgorithmsServerToClient(Buffer.from(this.config.mac_algorithms_server_to_client));
        // name-list    compression_algorithms_client_to_server
        algorithmNegotiation.setCompressionАlgorithmsClientToServer(Buffer.from(this.config.compression_algorithms_client_to_server));
        // name-list    compression_algorithms_server_to_client
        algorithmNegotiation.setCompressionAlgorithmsServerToClient(Buffer.from(this.config.compression_algorithms_server_to_client));
        // name-list    languages_client_to_server
        algorithmNegotiation.setLanguagesClientToServer(Buffer.from(""));
        // name-list    languages_server_to_client
        algorithmNegotiation.setLanguagesServerToClient(Buffer.from(""));
        // boolean      first_kex_packet_follows
        algorithmNegotiation.setFirstKexPacketFollows(false);
        
        // create payload
        let blockSize = 8;
        let payload = algorithmNegotiation.createPayload();
        // console.log("Visitor.sendKex payload:" + payload.length);
        let paddingLength: number = blockSize - (payload.length + 5) % blockSize;
        if (paddingLength < 4) {
            paddingLength += blockSize;
        }
        // console.log("Visitor.sendKex paddingLength:" + paddingLength);
        let padding: Buffer = Buffer.alloc(paddingLength);
        // console.log("Visitor.sendKex padding:" + padding.length);
        let packetLength: number = payload.length + paddingLength + 1;
        // console.log("Visitor.sendKex packetLength:" + packetLength);

        let writer = new BufferWriter();
        writer.appendInt32(packetLength);
        writer.appendByte(paddingLength);
        writer.appendBuffer(payload);
        writer.appendBuffer(padding);

        let towrite = writer.ToBuffer();

        // console.log("SEND KEX");
        // for (const pair of towrite.entries()) {
        //     console.log(pair);
        // }

        this.socket.write(towrite);
    }

    // TODO: create global value
    private buildStateMachine() : State {
        let initState = new State(States.init);
        let readSsh = new State(States.read_ssh_version);
        let readKeys = new State(States.read_keys);
        let keyExchage = new State(States.key_exchage);

        let lastStep = new State(States.last);

        initState.setNextState(readSsh)
            .setNextState(readKeys)
            .setNextState(keyExchage)
            
            
            .setNextState(lastStep);

        return initState;
    }
}