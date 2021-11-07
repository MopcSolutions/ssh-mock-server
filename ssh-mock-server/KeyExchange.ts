/*
SSH_MSG_KEXDH_INIT             30
*/
import { SshMsgKeys } from "./SshMggKeys";

export class KeyExchange {
    // TODO: user "Error"??
    private hasError: boolean = false;
    private error: string;
    private key: Buffer;
    constructor(data?: Buffer) {
        if(data != null) {
            this.readData(data);
        }
    }
    private readData(data: Buffer) {
        let offset: number = 0;
        let key = data.readInt8(offset);
        offset += 1;
        // must be SSH_MSG_KEXDH_INIT
        if(key != SshMsgKeys.SSH_MSG_KEXDH_INIT) {
            this.hasError = true;
            this.error = "key is not SSH_MSG_KEXDH_INIT";
            console.log("key is not SSH_MSG_KEXDH_INIT - " + key);
            return;
        }
        // read the rest
        let len = data.readUInt32BE(offset);
        offset += 4;
        this.key = data.subarray(offset, offset + len);
    }
    public getKey() : Buffer {
        return this.key;
    }
}