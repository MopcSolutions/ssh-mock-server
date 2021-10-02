/*
7.1.  Algorithm Negotiation

   Key exchange begins by each side sending the following packet:

      byte         SSH_MSG_KEXINIT
      byte[16]     cookie (random bytes)
      name-list    kex_algorithms
      name-list    server_host_key_algorithms
      name-list    encryption_algorithms_client_to_server
      name-list    encryption_algorithms_server_to_client
      name-list    mac_algorithms_client_to_server
      name-list    mac_algorithms_server_to_client
      name-list    compression_algorithms_client_to_server
      name-list    compression_algorithms_server_to_client
      name-list    languages_client_to_server
      name-list    languages_server_to_client
      boolean      first_kex_packet_follows
      uint32       0 (reserved for future extension)
*/

import { SshMsgKeys } from "./SshMggKeys";

export class AlgorithmNegotiation {
    private hasError: boolean = false;
    private error: string;
    private key: number;
    private cookie: Buffer;
    private kex_algorithms: any;
    private server_host_key_algorithms: any;
    private encryption_algorithms_client_to_server: any;
    private encryption_algorithms_server_to_client: any;
    private mac_algorithms_client_to_server: any;
    private mac_algorithms_server_to_client: any;
    private compression_algorithms_client_to_server: any;
    private compression_algorithms_server_to_client: any;
    private languages_client_to_server: any;
    private languages_server_to_client: any;
    private first_kex_packet_follows: any;
    // ctor
    constructor(data: Buffer) {
        let offset: number = 0;
        this.key = data.readInt8(offset);
        offset += 1;
        // must be SSH_MSG_KEXINIT
        if(this.key != SshMsgKeys.SSH_MSG_KEXINIT) {
            this.hasError = true;
            this.error = "key is not SSH_MSG_KEXINIT";
            console.log("key is not SSH_MSG_KEXINIT - " + this.key);
            return;
        }
        // read the rest
        this.cookie = data.subarray(offset, offset + 16);
        offset += 16;
        console.log("COOKIE");
        for (const pair of this.cookie.entries()) {
            console.log(pair);
        }
        // kex_algorithms
        let len = data.readUInt32BE(offset);
        offset += 4;
        console.log(offset);
        console.log(len);
        this.kex_algorithms = data.subarray(offset, offset + len);
        offset += len;
        console.log("KEX ALGORITMS");
        console.log(this.kex_algorithms.toString('utf8'));
        // server_host_key_algorithms
        len = data.readUInt32BE(offset);
        offset += 4;
        console.log(offset);
        console.log(len);
        this.server_host_key_algorithms = data.subarray(offset, offset + len);
        offset += len;
        console.log("SERVER HOST KEY ALGORITMS");
        console.log(this.server_host_key_algorithms.toString('utf8'));
        // encryption_algorithms_client_to_server
        len = data.readUInt32BE(offset);
        offset += 4;
        console.log(offset);
        console.log(len);
        this.encryption_algorithms_client_to_server = data.subarray(offset, offset + len);
        offset += len;
        console.log("ENCRYPTION ALGORITMS CLIENT TO SERVER");
        console.log(this.encryption_algorithms_client_to_server.toString('utf8'));
        // encryption_algorithms_server_to_client
        len = data.readUInt32BE(offset);
        offset += 4;
        console.log(offset);
        console.log(len);
        this.encryption_algorithms_server_to_client = data.subarray(offset, offset + len);
        offset += len;
        console.log("ENCRYPTION ALGORITMS SERVER TO CLIENT");
        console.log(this.encryption_algorithms_server_to_client.toString('utf8'));
        // mac_algorithms_client_to_server
        len = data.readUInt32BE(offset);
        offset += 4;
        console.log(offset);
        console.log(len);
        this.mac_algorithms_client_to_server = data.subarray(offset, offset + len);
        offset += len;
        console.log("MAC ALGORITMS CLIENT TO SERVER");
        console.log(this.mac_algorithms_client_to_server.toString('utf8'));
        // mac_algorithms_server_to_client
        len = data.readUInt32BE(offset);
        offset += 4;
        console.log(offset);
        console.log(len);
        this.mac_algorithms_server_to_client = data.subarray(offset, offset + len);
        offset += len;
        console.log("MAC ALGORITMS SERVER TO CLIENT");
        console.log(this.mac_algorithms_server_to_client.toString('utf8'));
        // compression_algorithms_client_to_server
        len = data.readUInt32BE(offset);
        offset += 4;
        console.log(offset);
        console.log(len);
        this.compression_algorithms_client_to_server = data.subarray(offset, offset + len);
        offset += len;
        console.log("COMPRESSION ALGORITMS CLIENT TO SERVER");
        console.log(this.compression_algorithms_client_to_server.toString('utf8'));
        // compression_algorithms_server_to_client
        len = data.readUInt32BE(offset);
        offset += 4;
        console.log(offset);
        console.log(len);
        this.compression_algorithms_server_to_client = data.subarray(offset, offset + len);
        offset += len;
        console.log("COMPRESSION ALGORITMS SERVER TO CLIENT");
        console.log(this.compression_algorithms_server_to_client.toString('utf8'));
        // languages_client_to_server
        len = data.readUInt32BE(offset);
        offset += 4;
        console.log(offset);
        console.log(len);
        this.languages_client_to_server = data.subarray(offset, offset + len);
        offset += len;
        console.log("LANGUAGES CLIENT TO SERVER");
        console.log(this.languages_client_to_server.toString('utf8'));
        // languages_server_to_client
        len = data.readUInt32BE(offset);
        offset += 4;
        console.log(offset);
        console.log(len);
        this.languages_server_to_client = data.subarray(offset, offset + len);
        offset += len;
        console.log("LANGUAGES SERVER TO CLIENT");
        console.log(this.languages_server_to_client.toString('utf8'));
        // languages_server_to_client
        let rest : Buffer = data.subarray(offset, data.length - offset);

// TODO: check offset ???

        console.log("---REST---");
        // console.log(data.toString('ascii'));
        // // view the contents
        // let algorythms : Buffer = data.subarray(offset, data.length - offset);
        // console.log(algorythms.toString('ascii'));
        for (const pair of rest.entries()) {
            console.log(pair);
        }
    }
    public HasError() : boolean {
        return this.hasError;
    }
    public Error() : string {
        return this.error;
    }
    public getKexAlgorithmsList() : Array<string> {
        let retval = new Array<string>();
        let list = this.kex_algorithms.toString('utf8').split(',');
        for(let val of list) {
            retval.push(val.trim());
        }
        return retval;
    }
    // TODO: implement other getters
}