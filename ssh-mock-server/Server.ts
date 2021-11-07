import net = require("net");
import crypto = require('crypto');
// import * as fs from 'fs';
import fs = require('fs');

import { base64encode, base64decode } from "nodejs-base64";

import { Visitor } from "./Visitor";
import { DatabaseFacade } from './DatabaseFacade'
import { ServerConfig } from './ServerConfig'
import { Util } from './Util'
export class Server {
    // change the server name on prod
    public static ProtocolVersionExchange: string = "SSH-2.0-ssh-mock-server";

    private static DefaultPort: number = 2222;
    private server: net.Server;
    private config: ServerConfig;

    public start(): void {
        // output node possibilities
        const keypair = crypto.generateKeyPairSync('ed25519', {
            privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
            publicKeyEncoding: { format: 'pem', type: 'spki' }
            }
        );
        console.log("keypair.privateKey");
        console.log(keypair.privateKey);
        console.log("keypair.publicKey");
        console.log(keypair.publicKey);
        // set defaults
        let port: number = Server.DefaultPort;

        // read config
        let json = fs.readFileSync('./config/serverconfig.json');
        this.config = JSON.parse(json.toString('utf8'));
        if(this.config != null) {
            console.log("Server.start reading config");
            port = this.config.port;
        }

        // subscribe event functions
        let s: net.Server = net.createServer();
        this.server = s.listen(port, null, 64);
        this.server.on("connection", this.onConnection.bind(this));
        this.server.on("error", this.onError.bind(this));
        this.server.on("listening", this.onListening.bind(this));
        this.server.on("close", this.onClose.bind(this));
    }

    private onConnection(s: net.Socket): void {
        let client : any = s.address();
        console.log("Server.onConnection: ");
        // remember visitor
        DatabaseFacade.IncrementVisitsCount(s);
        console.log(client.address);
        console.log(client.family);
        console.log(client.port);
        // decide if needs to be kicked at once
        if(DatabaseFacade.HasEnoughtData(s)) {
            s.end();
            s.destroy();
        } else {
            // just create one in memory for now
            new Visitor(s, this.config);
        }
    }

    private onClose(): void {
        console.log("Server.onClose.");
    }

    private onError(e: Error): void {
        console.log("Server.onError:");
        console.log(e.name);
        console.log(e.message);
        console.log(e.stack);
    }

    private onListening(): void {
        console.log("Server.onListening...");
    }
}