pub mod types {
    /// [Kerberos Message Types](https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.7)
    pub const AS_REQ_MSG_TYPE: u8 = 0x0a;
    pub const AS_REP_MSG_TYPE: u8 = 0x0b;
    pub const TGS_REQ_MSG_TYPE: u8 = 0x0c;
    pub const TGS_REP_MSG_TYPE: u8 = 0x0d;
    pub const AP_REQ_MSG_TYPE: u8 = 0x0e;
    pub const AP_REP_MSG_TYPE: u8 = 0x0f;
    pub const TGT_REQ_MSG_TYPE: u8 = 0x10;
    pub const TGT_REP_MSG_TYPE: u8 = 0x11;

    pub const KRB_PRIV: u8 = 21;
    pub const KRB_PRIV_ENC_PART: u8 = 28;

    pub const KRB_ERROR_MSG_TYPE: u8 = 0x1e;

    /// [Principal Names](https://datatracker.ietf.org/doc/html/rfc4120#section-6.2)
    pub const NT_UNKNOWN: u8 = 0x00;
    pub const NT_PRINCIPAL: u8 = 0x01;
    pub const NT_SRV_INST: u8 = 0x02;
    pub const NT_SRV_HST: u8 = 0x03;
    pub const NT_SRV_XHST: u8 = 0x04;
    pub const NT_UID: u8 = 0x05;
    pub const NT_X500_PRINCIPAL: u8 = 0x06;
    pub const NT_SMTP_NAME: u8 = 0x07;
    pub const NT_ENTERPRISE: u8 = 0x0A;

    /// [PreAuthentication Data Types](https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.2)
    pub const PA_ENC_TIMESTAMP: [u8; 1] = [0x02];
    pub const PA_ENC_TIMESTAMP_KEY_USAGE: i32 = 1;
    pub const PA_PAC_REQUEST_TYPE: [u8; 2] = [0x00, 0x80];
    pub const PA_ETYPE_INFO2_TYPE: [u8; 1] = [0x13];
    pub const PA_TGS_REQ_TYPE: [u8; 1] = [0x01];
    pub const PA_PAC_OPTIONS_TYPE: [u8; 2] = [0x00, 0xa7];

    pub const TICKET_TYPE: u8 = 1;
    pub const AUTHENTICATOR_TYPE: u8 = 2;
    pub const ENC_AS_REP_PART_TYPE: u8 = 25;
    pub const ENC_TGS_REP_PART_TYPE: u8 = 26;
    pub const ENC_AP_REP_PART_TYPE: u8 = 27;

    /// [Address Types](https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.3)
    pub const IP_V4_ADDR_TYPE: u8 = 2;
    pub const DIRECTIONAL_ADDR_TYPE: u8 = 3;
    pub const CHAOS_NET_ADDR_TYPE: u8 = 5;
    pub const XNS_ADDR_TYPE: u8 = 6;
    pub const ISO_ADDR_TYPE: u8 = 7;
    pub const DECNET_PHASE_IV_ADDR_TYPE: u8 = 12;
    pub const APPLETALK_DDP_ADDR_TYPE: u8 = 16;
    pub const NET_BIOS_ADDR_TYPE: u8 = 20;
    pub const IP_V6_ADDR_TYPE: u8 = 24;
}

pub mod key_usages {
    /// [GSS API Key Usages](https://datatracker.ietf.org/doc/html/rfc4121#section-2)
    pub const ACCEPTOR_SEAL: i32 = 22;
    pub const ACCEPTOR_SIGN: i32 = 23;
    pub const INITIATOR_SEAL: i32 = 24;
    pub const INITIATOR_SIGN: i32 = 25;
    /// [Key Usage Numbers](https://datatracker.ietf.org/doc/html/rfc4120#section-6.2)
    pub const KRB_PRIV_ENC_PART: i32 = 13;
}

/// [The Kerberos Version 5 GSS API](https://datatracker.ietf.org/doc/html/rfc4121)
pub mod gss_api {
    pub const AP_REQ_TOKEN_ID: [u8; 2] = [0x01, 0x00];
    pub const TGT_REQ_TOKEN_ID: [u8; 2] = [0x04, 0x00];
    pub const ACCEPT_COMPLETE: [u8; 3] = [0x0a, 0x01, 0x00];
    pub const ACCEPT_INCOMPLETE: [u8; 3] = [0x0a, 0x01, 0x01];

    pub const MIC_TOKEN_ID: [u8; 2] = [0x04, 0x04];
    pub const MIC_FILLER: [u8; 5] = [0xff, 0xff, 0xff, 0xff, 0xff];

    pub const WRAP_TOKEN_ID: [u8; 2] = [0x05, 0x04];
    pub const WRAP_FILLER: u8 = 0xff;

    /// [Authenticator Checksum](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1)
    pub const AUTHENTICATOR_CHECKSUM_TYPE: [u8; 3] = [0x00, 0x80, 0x03];
}

/// [Kerberos Change Password and Set Password Protocols](https://datatracker.ietf.org/doc/html/rfc3244)
pub mod krb_priv {
    pub const KRB_PRIV_VERSION: [u8; 2] = [0x00, 0x01];
}
