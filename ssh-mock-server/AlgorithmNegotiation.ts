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

import { read, write } from "fs";
import { SshMsgKeys } from "./SshMggKeys";
import { BufferWriter } from './BufferWriter'

export class AlgorithmNegotiation {
    private hasError: boolean = false;
    private error: string;
    private key: number;
    private cookie: Buffer;
    private kex_algorithms: Buffer;
    private server_host_key_algorithms: Buffer;
    private encryption_algorithms_client_to_server: Buffer;
    private encryption_algorithms_server_to_client: Buffer;
    private mac_algorithms_client_to_server: Buffer;
    private mac_algorithms_server_to_client: Buffer;
    private compression_algorithms_client_to_server: Buffer;
    private compression_algorithms_server_to_client: Buffer;
    private languages_client_to_server: Buffer;
    private languages_server_to_client: Buffer;
    private first_kex_packet_follows: boolean = false;
    // ctor
    constructor(data?: Buffer) {
        if(data != null) {
            this.readData(data);
        }
    }
    private readData(data: Buffer) {
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
        this.kex_algorithms = data.subarray(offset, offset + len);
        offset += len;
        // server_host_key_algorithms
        len = data.readUInt32BE(offset);
        offset += 4;
        this.server_host_key_algorithms = data.subarray(offset, offset + len);
        offset += len;
        // encryption_algorithms_client_to_server
        len = data.readUInt32BE(offset);
        offset += 4;
        this.encryption_algorithms_client_to_server = data.subarray(offset, offset + len);
        offset += len;
        // encryption_algorithms_server_to_client
        len = data.readUInt32BE(offset);
        offset += 4;
        this.encryption_algorithms_server_to_client = data.subarray(offset, offset + len);
        offset += len;
        // mac_algorithms_client_to_server
        len = data.readUInt32BE(offset);
        offset += 4;
        this.mac_algorithms_client_to_server = data.subarray(offset, offset + len);
        offset += len;
        // mac_algorithms_server_to_client
        len = data.readUInt32BE(offset);
        offset += 4;
        this.mac_algorithms_server_to_client = data.subarray(offset, offset + len);
        offset += len;
        // compression_algorithms_client_to_server
        len = data.readUInt32BE(offset);
        offset += 4;
        this.compression_algorithms_client_to_server = data.subarray(offset, offset + len);
        offset += len;
        // compression_algorithms_server_to_client
        len = data.readUInt32BE(offset);
        offset += 4;
        this.compression_algorithms_server_to_client = data.subarray(offset, offset + len);
        offset += len;
        // languages_client_to_server
        len = data.readUInt32BE(offset);
        offset += 4;
        this.languages_client_to_server = data.subarray(offset, offset + len);
        offset += len;
        // languages_server_to_client
        len = data.readUInt32BE(offset);
        offset += 4;
        this.languages_server_to_client = data.subarray(offset, offset + len);
        offset += len;
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
    public GetKexAlgorithmsList() : Array<string> {
        return this.ConvertListToArray(this.kex_algorithms);
    }
    public GetServerHostKeyAlgorithms() : Array<string> {
        return this.ConvertListToArray(this.server_host_key_algorithms);
    }
    public GetEncryptionAlgorithmsClientToServer() : Array<string> {
        return this.ConvertListToArray(this.encryption_algorithms_client_to_server);
    }
    public GetEncryptionAlgorithmsServerToClient() : Array<string> {
        return this.ConvertListToArray(this.encryption_algorithms_server_to_client);
    }
    public GetMacAlgorithmsClientToServer() : Array<string> {
        return this.ConvertListToArray(this.mac_algorithms_client_to_server);
    }
    public GetMacAlgorithmsServerToClient() : Array<string> {
        return this.ConvertListToArray(this.mac_algorithms_server_to_client);
    }
    public GetCompressionAlgorithmsClientToServer() : Array<string> {
        return this.ConvertListToArray(this.compression_algorithms_client_to_server);
    }
    public GetCompressionAlgorithmsServerToClient() : Array<string> {
        return this.ConvertListToArray(this.compression_algorithms_server_to_client);
    }
    public GetLanguagesClientToServer() : Array<string> {
        return this.ConvertListToArray(this.languages_client_to_server);
    }
    public GetLanguagesServerToClient() : Array<string> {
        return this.ConvertListToArray(this.languages_server_to_client);
    }
    public GetFirstKexPacketFollows() : boolean {
        return this.first_kex_packet_follows;
    }
    // TODO: is this name mesleading?
    private ConvertListToArray(data: Buffer) : Array<string> {
        let retval = new Array<string>();
        let list = data.toString('utf8').split(',');
        for(let val of list) {
            retval.push(val.trim());
        }
        return retval;
    }
    public setCookie(data: Buffer) {
        this.cookie = data;
    }
    public setKexAlgorithms(data: Buffer) {
        this.kex_algorithms = data;
    }
    public setServerHostKeyAlgorithms(data: Buffer) {
        this.server_host_key_algorithms = data;
    }
    public setEncryptionAlgorithmsClientToServer(data: Buffer) {
        this.encryption_algorithms_client_to_server = data;
    }
    public setEncryptionAlgorithmsServerToClient(data: Buffer) {
        this.encryption_algorithms_server_to_client = data;
    }
    public setMacAlgorithmsClientToServer(data: Buffer) {
        this.mac_algorithms_client_to_server = data;
    }
    public setMacAlgorithmsServerToClient(data: Buffer) {
        this.mac_algorithms_server_to_client = data;
    }
    public setCompressionАlgorithmsClientToServer(data: Buffer) {
        this.compression_algorithms_client_to_server = data;
    }
    public setCompressionAlgorithmsServerToClient(data: Buffer) {
        this.compression_algorithms_server_to_client = data;
    }
    public setLanguagesClientToServer(data: Buffer) {
        this.languages_client_to_server = data;
    }
    public setLanguagesServerToClient(data: Buffer) {
        this.languages_server_to_client = data;
    }
    public setFirstKexPacketFollows(flag: boolean) {
        this.first_kex_packet_follows = flag;
    }
    public createPayload() : Buffer {
        let writer : BufferWriter = new BufferWriter();

        writer.appendByte(SshMsgKeys.SSH_MSG_KEXINIT);
        writer.appendBuffer(this.cookie);
        // kex_algorithms
        writer.appendInt32(this.kex_algorithms.length);
        writer.appendBuffer(this.kex_algorithms);
        // server_host_key_algorithms
        writer.appendInt32(this.server_host_key_algorithms.length);
        writer.appendBuffer(this.server_host_key_algorithms);
        // encryption_algorithms_client_to_server
        writer.appendInt32(this.encryption_algorithms_client_to_server.length);
        writer.appendBuffer(this.encryption_algorithms_client_to_server);
        // encryption_algorithms_server_to_client
        writer.appendInt32(this.encryption_algorithms_server_to_client.length);
        writer.appendBuffer(this.encryption_algorithms_server_to_client);
        // mac_algorithms_client_to_server
        writer.appendInt32(this.mac_algorithms_client_to_server.length);
        writer.appendBuffer(this.mac_algorithms_client_to_server);
        // mac_algorithms_server_to_client
        writer.appendInt32(this.mac_algorithms_server_to_client.length);
        writer.appendBuffer(this.mac_algorithms_server_to_client);
        // compression_algorithms_client_to_server
        writer.appendInt32(this.compression_algorithms_client_to_server.length);
        writer.appendBuffer(this.compression_algorithms_client_to_server);
        // compression_algorithms_server_to_client
        writer.appendInt32(this.compression_algorithms_server_to_client.length);
        writer.appendBuffer(this.compression_algorithms_server_to_client);
        // languages_client_to_server
        writer.appendInt32(this.languages_client_to_server.length);
        writer.appendBuffer(this.languages_client_to_server);
        // languages_server_to_client
        writer.appendInt32(this.languages_server_to_client.length);
        writer.appendBuffer(this.languages_server_to_client);
        // first_kex_packet_follows
        writer.appendByte(this.first_kex_packet_follows ? 0x01 : 0x00);
        // int 32 = 0 (???)
        writer.appendInt32(0);
        
        return writer.ToBuffer();
    }
}