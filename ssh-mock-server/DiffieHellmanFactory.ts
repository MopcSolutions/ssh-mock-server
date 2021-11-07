import crypto = require("crypto");

export class DiffieHellmanFactory {
    public static GetDiffieHellman(name: string) : any {
        switch(name)
        {
            case "diffie-hellman-group14-sha1":
                return crypto.getDiffieHellman("modp14");
            case "diffie-hellman-group16-sha512":
                return crypto.getDiffieHellman("modp16");
            case "diffie-hellman-group18-sha512":
                return crypto.getDiffieHellman("modp18");
            default:
                return null;
        }
    }
}