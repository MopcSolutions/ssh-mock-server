import net = require("net");
import util = require("util");
import crypto = require('crypto');

import { Visitor } from "./Visitor";

export class Server {
    // change the server name on prod
    public static ProtocolVersionExchange: string = "SSH-2.0-ssh-mock-server";

    private static DefaultPort: number = 2222;

    private server: net.Server;

    public start(): void {
        // read from config
        let port: number = Server.DefaultPort;

        let s: net.Server = net.createServer();
        this.server = s.listen(port, null, 64);
        this.server.on("connection", this.onConnection.bind(this));
        this.server.on("error", this.onError.bind(this));
        this.server.on("listening", this.onListening.bind(this));
        this.server.on("close", this.onClose.bind(this));
    }

    private onConnection(s: net.Socket): void {
        console.log("New visitor: " + s.remoteAddress);
        // just create one in memory for now
        new Visitor(s);
    }

    private onClose(): void {
        console.log("close.");
    }

    private onError(e: Error): void {
        console.log("Error:");
        console.log(e.name);
        console.log(e.message);
        console.log(e.stack);
    }

    private onListening(): void {
        console.log("listening...");
    }

    public createKeys(): void {
        var prime_length = 60;
        var diffHell = crypto.createDiffieHellman(prime_length);
        
        diffHell.generateKeys('base64');
        console.log("Public Key : " ,diffHell.getPublicKey('base64'));
        console.log("Private Key : " ,diffHell.getPrivateKey('base64'));
        
        console.log("Public Key : " ,diffHell.getPublicKey('hex'));
        console.log("Private Key : " ,diffHell.getPrivateKey('hex'));
    }
}