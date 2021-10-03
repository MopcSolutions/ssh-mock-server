export class BufferWriter {
    private data: Array<number>;

    constructor() {
        this.data = new Array<number>();
    }

    public appendByte(n: number) {
        this.data.push(n);
    }
    public appendBuffer(buf: Buffer) {
        for(let byte of buf) {
            this.data.push(byte);
        }
    }
    public appendInt32(n: number) {
        let int = Buffer.alloc(4);
        int.writeUInt32BE(n);
        for(let byte of int) {
            this.data.push(byte);
        }
    }
    public ToBuffer() : Buffer {
        return Buffer.from(this.data);;
    }
}