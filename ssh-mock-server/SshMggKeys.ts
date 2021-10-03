export enum SshMsgKeys {
    SSH_MSG_DISCONNECT             = 1,
    SSH_MSG_IGNORE                 = 2,
    SSH_MSG_UNIMPLEMENTED          = 3,
    SSH_MSG_DEBUG                  = 4,
    SSH_MSG_SERVICE_REQUEST        = 5,
    SSH_MSG_SERVICE_ACCEPT         = 6,
    // algorithm negotiation
    SSH_MSG_KEXINIT                = 20,
    SSH_MSG_NEWKEYS                = 21,
    // client sends key
    SSH_MSG_KEXDH_INIT             = 30,
    // server sends key back
    SSH_MSG_KEXDH_REPLY            = 31,
}