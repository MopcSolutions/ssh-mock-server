import net = require("net");
import util = require("util");
import crypto = require("crypto");
import { stringify } from "querystring";
import { States } from './States';
import { State } from './State';
import { SshBufferReader } from './SshBufferReader'
import { AlgorithmNegotiation } from './AlgorithmNegotiation'

export class Visitor {
    // member variables
    private socket: net.Socket;
    private state: State;
    constructor(s: net.Socket) {
        this.socket = s;

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
                        this.socket.end();
                        this.socket.destroy();
                    }
                    break;
                case States.read_keys:
                    let bufferReader = new SshBufferReader(data);
                    let algorithmNegotiation = new AlgorithmNegotiation(bufferReader.getPayload())
                    if(algorithmNegotiation.HasError() == false) {
                        // check kex_algorithms
                        let algorithms = algorithmNegotiation.GetKexAlgorithmsList();
                        console.log("Visitor.onData LIST kex algorithms");
                        for(let val of algorithms) {
                            console.log(val);
                        }
                        // check server_host_key_algorithms
                        algorithms = algorithmNegotiation.GetServerHostKeyAlgorithms()
                        console.log("Visitor.onData LIST server host key algorithms");
                        for(let val of algorithms) {
                            console.log(val);
                        }
                        // check encryption_algorithms_client_to_server
                        algorithms = algorithmNegotiation.GetEncryptionAlgorithmsClientToServer();
                        console.log("Visitor.onData LIST encryption_algorithms_client_to_server");
                        for(let val of algorithms) {
                            console.log(val);
                        }
                        // check encryption_algorithms_server_to_client
                        algorithms = algorithmNegotiation.GetEncryptionAlgorithmsServerToClient();
                        console.log("Visitor.onData LIST encryption_algorithms_server_to_client");
                        for(let val of algorithms) {
                            console.log(val);
                        }
                        // check mac_algorithms_client_to_server
                        algorithms = algorithmNegotiation.GetMacAlgorithmsClientToServer();
                        console.log("Visitor.onData LIST mac_algorithms_client_to_server");
                        for(let val of algorithms) {
                            console.log(val);
                        }
                        // check mac_algorithms_server_to_client
                        algorithms = algorithmNegotiation.GetMacAlgorithmsServerToClient();
                        console.log("Visitor.onData LIST mac_algorithms_server_to_client");
                        for(let val of algorithms) {
                            console.log(val);
                        }
                        // check compression_algorithms_client_to_server
                        algorithms = algorithmNegotiation.GetCompressionAlgorithmsClientToServer();
                        console.log("Visitor.onData LIST compression_algorithms_client_to_server");
                        for(let val of algorithms) {
                            console.log(val);
                        }
                        // check compression_algorithms_server_to_client
                        algorithms = algorithmNegotiation.GetCompressionAlgorithmsServerToClient();
                        console.log("Visitor.onData LIST compression_algorithms_server_to_client");
                        for(let val of algorithms) {
                            console.log(val);
                        }
                        // check languages_client_to_server
                        algorithms = algorithmNegotiation.GetLanguagesClientToServer();
                        console.log("Visitor.onData LIST languages_client_to_server");
                        for(let val of algorithms) {
                            console.log(val);
                        }
                        // check languages_server_to_client
                        algorithms = algorithmNegotiation.GetLanguagesServerToClient();
                        console.log("Visitor.onData LIST languages_server_to_client");
                        for(let val of algorithms) {
                            console.log(val);
                        }
                        // SEND KEX TO VISITOR
                        this.sendKex();
                    }
                    this.state = this.state.getNextState();
                    break;
            }            
        }
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
        let data = Buffer.alloc(255);

        this.socket.write(data);
    }

    // TODO: create global value
    private buildStateMachine() : State {
        let initState = new State(States.init);
        let readSsh = new State(States.read_ssh_version);
        let readKeys = new State(States.read_keys);

        initState.setNextState(readSsh);
        readSsh.setNextState(readKeys);

        return initState;
    }
}