#![macro_escape]

#[cfg(not(debug))]
macro_rules! tls_err(
    ($kind:expr, $e:expr $($args:tt)*) => (
        ::tls_result::TlsError::new($kind, format!($e $($args)*))
    )
)

#[cfg(debug)]
macro_rules! tls_err(
    ($kind:expr, $e:expr $($args:tt)*) => (
        ::tls_result::TlsError::new($kind, format!($e $($args)*), file!(), line!())
    )
)

macro_rules! iotry(
    ($e:expr) => (
        {
            match $e {
                Ok(ok) => ok,
                Err(err) => {
                    return tls_err!(::tls_result::TlsErrorKind::IoFailure, "io error: {}", err);
                }
            }
        }
    )
)

macro_rules! num_size(
    (u8) => (1);
    (u16) => (2);
    (u24) => (3);
    (u32) => (4);
    (u64) => (8);
)

macro_rules! stry_write_num(
    (u8, $writer:expr, $e:expr) => ({
        iotry!($writer.write_u8($e as u8));
    });
    (u16, $writer:expr, $e:expr) => ({
        iotry!($writer.write_be_u16($e as u16));
    });
    (u24, $writer:expr, $e:expr) => (
        {
            let e = $e as u32;
            iotry!($writer.write_u8((e >> 16) as u8));
            iotry!($writer.write_u8((e >> 8) as u8));
            iotry!($writer.write_u8(e as u8));
        }
    );
    (u32, $writer:expr, $e:expr) => ({
        iotry!($writer.write_be_u32($e as u32));
    });
    (u64, $writer:expr, $e:expr) => ({
        iotry!($writer.write_be_u64($e as u64));
    });
)

macro_rules! stry_read_num(
    (u8, $reader:expr) => ({
        iotry!($reader.read_u8())
    });
    (u16, $reader:expr) => ({
        iotry!($reader.read_be_u16())
    });
    (u24, $reader:expr) => ({
        let n1 = iotry!($reader.read_u8()) as u32;
        let n2 = iotry!($reader.read_u8()) as u32;
        let n3 = iotry!($reader.read_u8()) as u32;
        (n1 << 16) | (n2 << 8) | n3
    });
    (u32, $reader:expr) => ({
        iotry!($reader.read_be_u32())
    });
    (u64, $reader:expr) => ({
        iotry!($reader.read_be_u64())
    });
)

macro_rules! tt_to_expr(
    ($num:expr) => ($num)
)
macro_rules! tt_to_pat(
    ($num:pat) => ($num)
)
