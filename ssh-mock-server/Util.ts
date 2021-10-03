export class Util {
    public static OutputArray(caption: string, array: any) {
        console.log(caption);
        for(let val of array) {
            console.log(val);
        }
    }
    public static OutputArrayAsPairs(caption: string, array: any) {
        console.log(caption);
        for (const pair of array.entries()) {
            console.log(pair);
        }
    }
}