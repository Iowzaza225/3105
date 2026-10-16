#!/usr/bin/env python3
"""Build17 native HouseArrest Documents transport.
RSD and app-specific authorization are required. No kernel exploit, no
arbitrary filesystem paths, and no writing outside OS-vended Documents.
"""
from pathlib import Path
import sys
root=Path(sys.argv[1])
rust=root/'pairing-native/src/lib.rs'
header=root/'pairing-native/include/ruizen_pairing.h'
manifest=root/'pairing-native/Cargo.toml'
def one(s,a,b):
    if s.count(a)!=1: raise SystemExit(f'Build17 native anchor count={s.count(a)}: {a[:80]!r}')
    return s.replace(a,b,1)
m=manifest.read_text()
m=one(m,'"tunnel_tcp_stack", "afc"]','"tunnel_tcp_stack", "afc", "house_arrest"]')
manifest.write_text(m)
r=rust.read_text()
r += r'''

// Build17 OS-authorized HouseArrest Documents transport. This service may deny
// the requested bundle ID, and denial is a final result, NOT bypassed.
use idevice::house_arrest::HouseArrestClient;

#[repr(C)]
pub struct RPAirLiftFileResult {
    pub stage: i32,
    pub message: *mut c_char,
    pub data: *mut u8,
    pub data_len: usize,
    pub data_capacity: usize,
    pub found: u8,
}

fn path_in_documents(path: &str) -> Result<String, (i32,String)> {
    // Swift PatchRules always specify paths rooted at the target app container.
    // HouseArrest VendDocuments is already rooted in Documents.
    let rel = path.strip_prefix("Documents/")
        .ok_or((30, "AirLift currently supports Documents/ paths only".to_string()))?;
    let components: Vec<&str> = rel.split('/').collect();
    if rel.len() > 2048 || components.is_empty() || components.iter().any(
        |c| c.is_empty() || *c == "." || *c == ".." || c.contains('\\') || c.contains(':') || c.contains('\0')
    ) {
        return Err((30, "Unsafe or invalid Documents path".to_string()));
    }
    Ok(rel.to_string())
}

async fn airlift_file_op(
    record_path: String, host: String, bundle: String, path: String,
    action: u32, payload: Vec<u8>,
) -> Result<(bool,Vec<u8>), (i32,String)> {
    if bundle.len() > 255 || !bundle.contains('.') || bundle.contains('/')
       || bundle.contains('\\') || bundle.contains('\0') {
        return Err((30,"Invalid app bundle ID".to_string()));
    }
    let target = path_in_documents(&path)?;
    if payload.len() > 8 * 1024 * 1024 {
        return Err((30,"Single-file transfer limit is 8 MB".to_string()));
    }
    let data = std::fs::read(record_path)
        .map_err(|_| (31,"Cannot open existing pairing record".to_string()))?;
    let mut pairing = RpPairingFile::from_bytes(&data)
        .map_err(|_| (31,"Invalid pairing record".to_string()))?;
    let sock = tokio::time::timeout(Duration::from_secs(6),
        tokio::net::TcpStream::connect(("10.7.0.1",49152)))
        .await.map_err(|_| (32,"Pairing TCP timeout".to_string()))?
        .map_err(|_| (32,"Pairing TCP not available".to_string()))?;
    let mut client = RemotePairingClient::new(RpPairingSocket::new(sock), "RUIZEN CLIENT");
    tokio::time::timeout(Duration::from_secs(12), client.attempt_pair_verify())
        .await.map_err(|_|(33,"Pairing handshake timed out".to_string()))?
        .map_err(|_|(33,"Pairing handshake rejected".to_string()))?;
    tokio::time::timeout(Duration::from_secs(12), client.validate_pairing(&mut pairing))
        .await.map_err(|_|(34,"Pair-Verify timed out".to_string()))?
        .map_err(|_|(34,"Pair-Verify failed".to_string()))?;
    let tunnel_port = tokio::time::timeout(Duration::from_secs(12), client.create_tcp_listener())
        .await.map_err(|_|(35,"Tunnel listener request timeout".to_string()))?
        .map_err(|_|(35,"Tunnel listener rejected".to_string()))?;
    if tunnel_port == 0 {
        return Err((35,"Device returned no tunnel port".to_string()));
    }
    let sock = tokio::time::timeout(Duration::from_secs(8),
        tokio::net::TcpStream::connect(("10.7.0.1", tunnel_port)))
        .await.map_err(|_|(36,"Secure tunnel TCP timeout".to_string()))?
        .map_err(|_|(36,"Secure tunnel TCP failed".to_string()))?;
    let psk = client.encryption_key().to_vec();
    let tunnel = tokio::time::timeout(Duration::from_secs(20),connect_tls_psk_tunnel_native(sock,&psk))
        .await.map_err(|_|(37,"TLS-PSK/CDTunnel timeout".to_string()))?
        .map_err(|_|(37,"TLS-PSK/CDTunnel failed".to_string()))?;
    let info = tunnel.info.clone();
    if info.server_rsd_port == 0 {
        return Err((38,"CDTunnel has no RSD service".to_string()));
    }
    let our_ip: IpAddr = info.client_address.parse()
        .map_err(|_|(38,"Invalid tunnel client address".to_string()))?;
    let peer_ip: IpAddr = info.server_address.parse()
        .map_err(|_|(38,"Invalid tunnel peer address".to_string()))?;
    let mut adapter = Adapter::new(Box::new(tunnel.into_inner()),our_ip,peer_ip);
    adapter.set_mss((info.mtu as usize).saturating_sub(60));
    let mut handle = adapter.to_async_handle();
    let stream=tokio::time::timeout(Duration::from_secs(15),handle.connect(info.server_rsd_port))
        .await.map_err(|_|(39,"RSD TCP timeout".to_string()))?
        .map_err(|_|(39,"RSD TCP failed".to_string()))?;
    let mut rsd=tokio::time::timeout(Duration::from_secs(20),RsdHandshake::new(stream))
        .await.map_err(|_|(40,"RSD handshake timeout".to_string()))?
        .map_err(|_|(40,"RSD handshake failed".to_string()))?;
    if !rsd.services.contains_key("com.apple.mobile.house_arrest.shim.remote") {
        return Err((41,"HouseArrest is not advertised by iOS; target app Documents is unavailable".to_string()));
    }
    let house=tokio::time::timeout(Duration::from_secs(20),
        rsd.connect::<HouseArrestClient>(&mut handle))
        .await.map_err(|_|(42,"HouseArrest connection timed out".to_string()))?
        .map_err(|_|(42,"HouseArrest service denied the connection".to_string()))?;
    let mut afc=tokio::time::timeout(Duration::from_secs(20),house.vend_documents(bundle))
        .await.map_err(|_|(43,"Target app Documents access timed out".to_string()))?
        .map_err(|_|(43,"iOS denied access to that app's Documents; no bypass attempted".to_string()))?;
    let bits: Vec<&str> = target.split('/').collect();
    let parent=if bits.len() > 1 { bits[..bits.len()-1].join("/") } else { ".".to_string() };
    let entries=afc.list_dir(&parent).await
        .map_err(|_|(44,"The target Documents subdirectory is unavailable".to_string()))?;
    let exists=entries.iter().any(|x| x==bits[bits.len()-1]);
    // AFC must not be asked to follow an existing symlink target.
    if exists {
        let metadata=afc.get_file_info_raw(target.clone()).await
            .map_err(|_|(44,"Could not inspect target file".to_string()))?;
        if metadata.get("st_ifmt").map(|x|x.as_str()) == Some("S_IFLNK") {
            return Err((44,"Symlink targets are not permitted".to_string()));
        }
    }
    match action {
        0 => {
            if !exists { return Ok((false,Vec::new())) }
            let mut file=afc.open(target,AfcFopenMode::RdOnly).await
                .map_err(|_|(45,"Target file read denied".to_string()))?;
            let data=file.read_entire().await
                .map_err(|_|(45,"Target file reading failed".to_string()))?;
            file.close().await
                .map_err(|_|(45,"Target file close failed".to_string()))?;
            if data.len()>8*1024*1024 {
                return Err((45,"Remote file too large for safe transaction backup".to_string()));
            }
            Ok((true,data))
        }
        1 => {
            let mut file=afc.open(target.clone(),AfcFopenMode::Wr).await
                .map_err(|_|(46,"AFC did not permit writing the target file".to_string()))?;
            file.write_entire(&payload).await
                .map_err(|_|(46,"AFC write was rejected".to_string()))?;
            file.close().await.map_err(|_|(46,"Failed to close AFC written file".to_string()))?;
            let mut file=afc.open(target,AfcFopenMode::RdOnly).await
                .map_err(|_|(47,"AFC read-back open denied".to_string()))?;
            let received=file.read_n(payload.len()).await
                .map_err(|_|(47,"AFC read-back failed".to_string()))?;
            file.close().await.map_err(|_|(47,"Failed to close read-back file".to_string()))?;
            if received!=payload { return Err((47,"AFC write/read-back mismatch".to_string())); }
            Ok((true,Vec::new()))
        }
        2 => {
            if exists {
                afc.remove(target).await
                    .map_err(|_|(48,"AFC denied removing transaction-created file".to_string()))?;
            }
            Ok((false,Vec::new()))
        }
        _ => Err((30,"Invalid file operation".to_string()))
    }
}

/// # Safety
/// Callers provide valid NUL-terminated path/bundle strings and writable out.
/// Payload may be null iff payload_len is zero. Read results are freed with
/// rp_airlift_file_result_free, including the status C string.
#[no_mangle]
pub unsafe extern "C" fn rp_airlift_documents_file_op(
    record_path: *const c_char, bundle: *const c_char, target: *const c_char,
    action: u32, payload: *const u8, payload_len: usize,
    out: *mut RPAirLiftFileResult,
) -> i32 {
    if out.is_null() {return 2}
    (*out)=RPAirLiftFileResult {stage:0,message:ptr::null_mut(),
        data:ptr::null_mut(),data_len:0,data_capacity:0,found:0};
    if record_path.is_null()||bundle.is_null()||target.is_null()||
       (payload_len>0 && payload.is_null()) ||payload_len>8*1024*1024 {
        (*out).stage=30; (*out).message=into_c("Invalid arguments"); return 1;
    }
    let p=as_string(record_path,"");
    let b=as_string(bundle,"");
    let t=as_string(target,"");
    let bytes=if payload_len>0 {std::slice::from_raw_parts(payload,payload_len).to_vec()}
              else {Vec::new()};
    let thread=std::thread::Builder::new().stack_size(8*1024*1024).spawn(move||{
        let rt=tokio::runtime::Builder::new_current_thread().enable_all().build()
            .map_err(|_|(30,"Could not initialize AirLift worker".to_string()))?;
        rt.block_on(airlift_file_op(p,"10.7.0.1".to_string(),b,t,action,bytes))
    });
    let outcome=match thread {
        Ok(th)=>th.join().unwrap_or_else(|_|Err((30,"AirLift worker panic".to_string()))),
        Err(_)=>Err((30,"Could not launch AirLift worker".to_string()))
    };
    match outcome {
        Ok((found,mut bytes))=>{
            (*out).stage=50;
            (*out).found=if found{1}else{0};
            (*out).data_len=bytes.len();
            (*out).data_capacity=bytes.capacity();
            if !bytes.is_empty(){
                (*out).data=bytes.as_mut_ptr();
                std::mem::forget(bytes);
            }
            (*out).message=into_c("AirLift Documents operation and verification succeeded");
            0
        }
        Err((stage,message))=>{
            (*out).stage=stage;
            (*out).message=into_c(message);
            1
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn rp_airlift_file_result_free(out: *mut RPAirLiftFileResult){
    if out.is_null(){return}
    if !(*out).message.is_null(){let _=CString::from_raw((*out).message);}
    if !(*out).data.is_null(){
        let _=Vec::from_raw_parts((*out).data,(*out).data_len,(*out).data_capacity);
    }
    (*out)=RPAirLiftFileResult{stage:0,message:ptr::null_mut(),data:ptr::null_mut(),
        data_len:0,data_capacity:0,found:0};
}
'''
rust.write_text(r)
h=header.read_text()
h += '''

// iOS27 OS-authorized app Documents only. No sandbox bypass.
typedef struct RPAirLiftFileResult {
    int32_t stage;
    char *message;
    uint8_t *data;
    size_t data_len;
    size_t data_capacity;
    uint8_t found;
} RPAirLiftFileResult;
int32_t rp_airlift_documents_file_op(const char *record_path, const char *bundle,
    const char *target, uint32_t action, const uint8_t *payload,
    size_t payload_len, RPAirLiftFileResult *out);
void rp_airlift_file_result_free(RPAirLiftFileResult *out);
'''
header.write_text(h)
print("Build17: native HouseArrest Documents read/write/delete with RSD authorization")
