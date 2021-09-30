import net = require("net");
import util = require("util");
import crypto = require("crypto");
import { stringify } from "querystring";

export class Visitor {
    // member variables
    private socket: net.Socket;
    constructor(s: net.Socket) {
        this.socket = s;

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
        this.sendString("SSH-2.0-ssh-mock-server\r\n");
    }

    // Emitted once the socket is fully closed. The argument hadError is a boolean which says if the socket was closed due to a transmission error.
    private onClose(hadError: boolean): void {
        console.log("visitor " + this.socket.remoteAddress + " closed");
    }

    // Emitted when a socket connection is successfully established. See net.createConnection().
    private onConnect(): void {
        console.log("Visitor.onConnect: " + this.socket.remoteAddress);
    }

    // Emitted when data is received. The argument data will be a Buffer or String. Encoding of data is set by socket.setEncoding().
    private onData(data: any): void {
        if(data instanceof String) {
            console.log("Visitor.onData: " + data);
        }
        if(data instanceof Buffer) {
            let b: Buffer = data;
            console.log("Visitor.onData");
            let value : number = b[0];
            if(value > 0) {
                console.log(data.toString('utf8'));
            }
            else {
                // TODO: check what it means
                // TODO: check what is going on here
                for (const pair of b.entries()) {
                    // console.log(pair);
                }
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
}