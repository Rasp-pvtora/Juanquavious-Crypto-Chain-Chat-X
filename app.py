# app.py — ChainChat X v8.2: Invite Fixed + Live Hash + Offline Decrypt + UI
import streamlit as st
import json, os, base64, secrets, hashlib, datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === CONFIG ===
ACTIVE_DEBUG = False  # Set to True to show debug info

# === AUTO LOAD ===
def load(path, name):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

try:
    import qrcode, PIL
except ImportError:
    print("[ChainChat] Installing missing deps...")
    import subprocess, sys
    subprocess.check_call([sys.executable, "import.py"])
    os.execv(sys.executable, [sys.executable] + sys.argv)

im = load("import.py", "im"); im.check()
vs = load("verify_settings.py", "vs"); vs.run()
crypto_mod = load("crypto.py", "StealthCrypto")
sc = crypto_mod.StealthCrypto

st.set_page_config(page_title="ChainChat X v8.2", layout="wide")
st.title("ChainChat X v8.2")

USERS = "users"
CHAINS = "chains"
for d in [USERS, CHAINS]: os.makedirs(d, exist_ok=True)

if "user" not in st.session_state: st.session_state.user = None
if "page" not in st.session_state: st.session_state.page = "login"

def save_user(u): open(f"{USERS}/{u['main_id']}.json", "w").write(json.dumps(u, indent=2))
def load_user(mid): return json.load(open(f"{USERS}/{mid}.json")) if os.path.exists(f"{USERS}/{mid}.json") else None
def save_chain(cid, data): open(f"{CHAINS}/chat_{cid}.chain", "w").write(json.dumps(data, indent=2))
def load_chain(cid): return json.load(open(f"{CHAINS}/chat_{cid}.chain")) if os.path.exists(f"{CHAINS}/chat_{cid}.chain") else None

# === LOGIN ===
if st.session_state.page == "login":
    st.subheader("Create / Login Agent")
    col1, col2 = st.columns([1, 1])
    with col1:
        name = st.text_input("Name")
        pw = st.text_input("Password", type="password")
        if st.button("Login / Create"):
            if not name or not pw: st.error("Fill both")
            else:
                uid = sc.hash_id(name, pw)
                user = load_user(uid)
                if not user:
                    keys = sc.gen_keys()
                    pub_bytes = base64.b64decode(keys["pub"])
                    keys["pub_hex"] = pub_bytes.hex()
                    user = {
                        "main_id": uid,
                        "real_name": name,
                        "pw_hash": hashlib.sha256(pw.encode()).hexdigest(),
                        "keys": keys,
                        "nickname": secrets.token_hex(4),
                        "chains": []
                    }
                    save_user(user)
                    st.success(f"Agent {name} created")
                elif user["pw_hash"] != hashlib.sha256(pw.encode()).hexdigest():
                    st.error("Wrong password")
                else:
                    st.success(f"Welcome back, {name}")
                st.session_state.user = user
                st.session_state.page = "home"
                st.rerun()
    with col2:
        id_file = st.file_uploader("Drop Identity File (.json)", type=".json")
        if id_file:
            try:
                user = json.load(id_file)
                if "main_id" not in user or "keys" not in user:
                    st.error("Invalid identity")
                else:
                    if "pub_hex" not in user["keys"]:
                        pub_bytes = base64.b64decode(user["keys"]["pub"])
                        user["keys"]["pub_hex"] = pub_bytes.hex()
                    if "nickname" not in user:
                        user["nickname"] = secrets.token_hex(4)
                    save_user(user)
                    st.session_state.user = user
                    st.session_state.page = "home"
                    st.success("Logged in via file")
                    st.rerun()
            except Exception as e:
                st.error(f"Invalid file: {e}")

# === HOME ===
if st.session_state.page == "home" and st.session_state.user:
    user = st.session_state.user
    
    # === EARLY pub_hex (CRITICAL) ===
    if "pub_hex" not in user["keys"]:
        pub_bytes = base64.b64decode(user["keys"]["pub"])
        user["keys"]["pub_hex"] = pub_bytes.hex()
        save_user(user)
    pub_hex = user["keys"]["pub_hex"].lower()  # lowercase for consistency

    # === LAYOUT ===
    left_col, main_col = st.columns([1, 3])

    with left_col:
        st.subheader("📋 Manage Channels")
        
        if st.button("New Channel"):
            cid = secrets.token_hex(4)
            chat_key = secrets.token_bytes(32)
            members = {pub_hex: pub_hex}
            blobs = {pub_hex: sc.encrypt_key(chat_key, pub_hex)}
            colors = {pub_hex: "#90EE90"}
            chain = {
                "chat_id": cid,
                "members": members,
                "key_blobs": blobs,
                "messages": [],
                "user_colors": colors,
                "version": 8
            }
            save_chain(cid, chain)
            user["chains"].append(cid)
            save_user(user)
            st.rerun()

        chain_files = [f for f in os.listdir(CHAINS) if f.endswith(".chain")]
        for f in chain_files:
            cid = f.replace("chat_", "").replace(".chain", "")
            if cid in user["chains"]:
                if st.button(f"chat_{cid[:8]}", key=f"open_{cid}"):
                    st.session_state.selected = cid
                    st.rerun()

        st.markdown("---")
        chain_file = st.file_uploader("Import .chain", type=".chain")
        if chain_file:
            try:
                # read bytes once (avoid reading the same stream twice)
                content = chain_file.getvalue()
                data = json.loads(content)
                cid = data["chat_id"]
                path = f"{CHAINS}/chat_{cid}.chain"
                with open(path, "wb") as f:
                    f.write(content)
                if cid not in user.get("chains", []):
                    user.setdefault("chains", []).append(cid)
                    save_user(user)
                    # ensure session state is in sync so the new channel appears immediately
                    st.session_state.user = user
                st.success(f"Imported: chat_{cid}")
                st.rerun()
            except Exception as e:
                st.error(f"Invalid file: {e}")
    with main_col:

        #st.subheader("💬 Channel Chat")
        # Split into two columns for IDs
        # === YOUR PUBLIC KEY (MOVED BELOW "Manage Channels") ===
        st.markdown("---")
        st.markdown("**Your Invite Key (64-char Public Key)**")
        key_col1, key_col2 = st.columns([5, 1])
        with key_col1:
            st.code(pub_hex, language=None)
        with key_col2:
            if st.button("Copy Key", key="copy_pubkey"):
                js = f"""
                <script>
                navigator.clipboard.writeText("{pub_hex}");
                </script>
                """
                st.components.v1.html(js, height=0)
                st.toast("Key copied!", icon="📋")
        st.caption("<small style='color: #888;'>Give this key to others to join their chat 💬</small>", unsafe_allow_html=True)


        if "selected" not in st.session_state:
            st.info("Select a channel or create new")
        else:
            cid = st.session_state.selected
            chain = load_chain(cid)
            
            # Debug info
            if ACTIVE_DEBUG:
                st.write("DEBUG:")
                st.write("Your pub_hex:", pub_hex)
                st.write("Chain members:", chain.get("members", {}))
                st.write("Key blobs for:", list(chain.get("key_blobs", {}).keys()))
                
                if not chain:
                    st.error("Chain not found")
                    del st.session_state.selected
                    st.rerun()

            # --- Normalize member/key blob keys to lowercase to avoid mismatches
            def _norm_keys(d):
                return {k.lower(): v for k, v in (d or {}).items()}

            chain["members"] = _norm_keys(chain.get("members", {}))
            chain["key_blobs"] = _norm_keys(chain.get("key_blobs", {}))
            chain["user_colors"] = _norm_keys(chain.get("user_colors", {}))
            # Save normalized chain back so future loads are consistent
            save_chain(cid, chain)
            # Ensure our local pub_hex is lowercase for comparisons
            pub_hex = pub_hex.lower()

            # === CHANNEL INFO ===
            st.markdown(f"**Channel name:** `{cid}`")
            st.markdown(f"**Chat Members:** [{len(chain['members'])}]")

            my_pub = pub_hex.lower()
            # Vertical dot list
            for pub in chain["members"]:
                pub_lower = pub.lower()
                is_me_member = pub_lower == my_pub

                # Try to get nick from messages
                nick = pub[:8]
                for m in chain["messages"]:
                    if m.get("sender_pub") == pub:
                        nick = m.get("sender_nick", pub[:8])
                        break
                
                # === SAME LOGIC AS BUBBLES ===
                canonical_color = chain["user_colors"].get(pub_lower, "#CCCCCC")
                if is_me_member:
                    display_color = "#90EE90"  # I AM GREEN
                elif canonical_color == "#90EE90":
                    my_original = chain["user_colors"].get(my_pub, "#87CEEB")
                    display_color = my_original
                else:
                    display_color = canonical_color

                #color = chain["user_colors"].get(pub, "#CCCCCC")
                st.markdown(f"<span style='color:{display_color};font-size:20px'>●</span> {nick}", unsafe_allow_html=True)

            # Compute local access (decrypted chat key) BEFORE invite & messages UI
            access = None
            try:
                priv_bytes = base64.b64decode(user["keys"]["priv"])
                b64_priv = base64.b64encode(priv_bytes).decode()
                for member_pub in chain.get("members", {}):
                    if member_pub == pub_hex and member_pub in chain.get("key_blobs", {}):
                        try:
                            access = sc.decrypt_key(chain["key_blobs"][member_pub], b64_priv)
                            break
                        except Exception:
                            access = None
            except Exception:
                access = None

            # Add this debug block right before access check
            if ACTIVE_DEBUG:
                st.write("MORE DEBUG:")
                st.write("User file pub_hex:", user["keys"]["pub_hex"])
                st.write("Base64 pub decoded to hex:", base64.b64decode(user["keys"]["pub"]).hex())
                st.write("Your current pub_hex (lowercased):", pub_hex)
                st.write("Is your pub in members?", pub_hex in chain["members"])
                st.write("Is your pub in key_blobs?", pub_hex in chain["key_blobs"])

                if not access:
                    st.error("Cannot decrypt channel key (you may not have access)")
                    st.stop()

            # === INVITE AGENT ===
            st.markdown("---")
            col_inv1, col_inv2 = st.columns([4, 1])
            with col_inv1:
                invite_pub = st.text_input("Invite by 64-char hex public key", key=f"inv_{cid}")
            with col_inv2:
                if st.button("Add", key=f"add_{cid}"):
                    invite_pub = invite_pub.strip().lower()
                    if len(invite_pub) != 64:
                        st.error("64 hex chars")
                    else:
                        try:
                            bytes.fromhex(invite_pub)
                            if invite_pub in chain["members"]:
                                st.error("Already in")
                            else:
                                # use decrypted access (the chat key bytes) to create the blob for the new member
                                blob = sc.encrypt_key(access, invite_pub)
                                chain["members"][invite_pub] = invite_pub
                                chain["key_blobs"][invite_pub] = blob
                                # Auto color
                                if invite_pub not in chain["user_colors"]:
                                    chain["user_colors"][invite_pub] = "#FFB3BA"  # pastel
                                save_chain(cid, chain)
                                st.success(f"Added: {invite_pub[:8]}...")
                                st.rerun()
                        except Exception:
                            st.error("Invalid")

            st.markdown("---")

            # === MESSAGES ===
            # access is already computed above
            def hex_to_rgb(h):
                h = h.lstrip('#')
                if len(h) == 3:
                    h = ''.join(ch*2 for ch in h)
                try:
                    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
                except:
                    return (200,200,200)
            
            html = ['<div style="display:flex;flex-direction:column;gap:8px;">']
            for m in chain.get("messages", []):
                sender = m.get("sender_pub", "").lower()
                nick = m.get("sender_nick", sender[:8])
                # try decrypt if ciphertext present
                text = None
                try:
                    if "ciphertext" in m:
                        try:
                            text = sc.dec_msg(m, access)
                        except Exception:
                            text = "[decryption error]"
                    elif "text" in m:
                        text = m["text"]
                    elif "payload" in m:
                        text = m["payload"]
                    else:
                        text = str(m)
                except Exception:
                    text = "[error]"

                # remove redundant "nick: " prefix (many messages were stored as "nick: message")
                try:
                    prefix = f"{nick}: "
                    if isinstance(text, str) and text.startswith(prefix):
                        text = text[len(prefix):]
                except:
                    pass

                # === NORMALIZE PUB KEYS ===
                my_pub = pub_hex.lower()
                is_me = (sender == pub_hex)
                # === CANONICAL COLOR FROM CHAIN (NEVER MODIFIED) ===
                canonical_color = chain["user_colors"].get(sender, "#CCCCCC")

                if ACTIVE_DEBUG:
                    st.write("DEBUG:")
                    st.write("My pub_hex:", pub_hex)
                    st.write("Sender pub:", m.get("sender_pub"))
                    st.write("is_me:", m.get("sender_pub") == pub_hex)
                    st.write("user_colors keys:", list(chain["user_colors"].keys()))
                    
                # bubble colors
                # === UI DISPLAY COLOR: I AM GREEN, OTHERS SWAP IF NEEDED ===
                if is_me:
                    display_color = "#90EE90"  # I AM GREEN
                elif canonical_color == "#90EE90":
                    # Someone else had green → give them MY original color
                    my_original_color = chain["user_colors"].get(my_pub, "#87CEEB")
                    display_color = my_original_color
                else:
                    display_color = canonical_color

                # === ALIGNMENT ===
                align = "flex-end" if is_me else "flex-start"
                radius = "12px 12px 0 12px"
                border = "none"
                bubble_color = "#111"

                # small header with nick (left)
                header = f'<div style="font-size:12px;color:#666;margin-bottom:6px;">{nick}</div>'

                bubble = (
                    f'<div style="max-width:78%; display:inline-block; background:{display_color}; color:{bubble_color}; '
                    f'padding:10px; border-radius:{radius}; border:{border}; box-shadow: rgba(0,0,0,0.02) 0 1px 0;">'
                    f'{text}</div>'
                )

                # format timestamp for display (fallback to raw value)
                raw_ts = m.get("timestamp", "") or m.get("time", "")
                time_display = raw_ts
                try:
                    if raw_ts:
                        # supports ISO like "YYYY-MM-DDTHH:MM:SS(.micro)?Z"
                        iso = raw_ts.replace("Z", "")
                        dt = datetime.datetime.fromisoformat(iso)
                        time_display = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    time_display = raw_ts

                time_html = f'<div style="font-size:11px;color:#666;margin-top:6px;{"text-align:right;" if is_me else ""}">{time_display}</div>'

                html.append(
                    f'<div style=\"display:flex;justify-content:{align};\">'
                    f'<div style=\"display:flex;flex-direction:column;align-items:{"flex-end" if is_me else "flex-start"};\">'
                    f'{header}{bubble}{time_html}</div></div>'
                )

            html.append('</div>')
            st.markdown("".join(html), unsafe_allow_html=True)

            # === INPUT + LIVE HASH ===
            st.markdown("---")
            msg_input = st.text_area("Your message", key=f"msg_{cid}", height=80, 
                                   placeholder="Type here...", 
                                   label_visibility="collapsed")
            
            # LIVE HASH — REAL-TIME
                        # === LIVE HASH & SEND ===
            live_ciphertext = ""
            live_hash = ""
            if msg_input:
                preview = f"{user['nickname']}: {msg_input}"
                now = datetime.datetime.utcnow().isoformat() + "Z"
                enc = sc.enc_msg(preview, access)
                live_ciphertext = enc["ciphertext"]
                live_hash = hashlib.sha256(base64.b64decode(live_ciphertext)).hexdigest()
                st.markdown(f"**Message ID:** `{live_hash}`")
                st.markdown(f"**Ciphertext (for offline send):**")
                st.code(live_ciphertext, language=None)

            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("Save", key=f"save_{cid}"):
                    if msg_input:
                        preview = f"{user['nickname']}: {msg_input}"
                        now = datetime.datetime.utcnow().isoformat() + "Z"
                        enc = sc.enc_msg(preview, access)
                        enc.update({
                            "sender_pub": pub_hex,
                            "sender_nick": user["nickname"],
                            "timestamp": now,
                            "hash": hashlib.sha256(base64.b64decode(enc["ciphertext"])).hexdigest()
                        })
                        chain["messages"].append(enc)
                        save_chain(cid, chain)
                        st.success("Saved!")
                        st.rerun()

            with col2:
                path = f"{CHAINS}/chat_{cid}.chain"
                with open(path, "rb") as f:
                    st.download_button("Export Chain", f.read(), f"chat_{cid}.chain", key=f"exp_{cid}")

            with col3:
                if live_ciphertext:
                    js = f"""
                    <script>
                    navigator.clipboard.writeText("{live_ciphertext}");
                    </script>
                    """
                    if st.button("Copy Ciphertext", key=f"copy_ct_{cid}"):
                        st.components.v1.html(js, height=0)
                        st.toast("Ciphertext copied!")

            # === OFFLINE DECRYPT ===
            st.markdown("---")
            st.markdown("**Decrypt Offline Message**")
            ct_input = st.text_area("Paste ciphertext here (base64)", key=f"ctin_{cid}", height=100)
            if st.button("Decrypt", key=f"dec_ct_{cid}"):
                if ct_input.strip():
                    try:
                        data = base64.b64decode(ct_input.strip())
                        if len(data) < 12:
                            st.error("Invalid ciphertext: too short")
                        else:
                            nonce, ct = data[:12], data[12:]
                            aes = AESGCM(access)
                            text = aes.decrypt(nonce, ct, None).decode()
                            st.success(f"**Decrypted:** {text}")
                    except Exception as e:
                        st.error(f"Cannot decrypt: {str(e)}")
                else:
                    st.error("Paste a ciphertext")

    # === RIGHT SIDEBAR ===
    with st.sidebar:
        st.markdown("---")
        st.markdown(f"**Agent:** {user.get('real_name', 'CLASSIFIED')}")
        st.markdown(f"**Main ID:** {user['main_id'][:8]}...")

        nick = st.text_input("Nickname", value=user["nickname"], key="nick_input")
        if nick != user["nickname"]:
            user["nickname"] = nick
            save_user(user)
            st.rerun()

        if st.button("Change Password"):
            new_pw = st.text_input("New Password", type="password", key="newpw")
            if new_pw and st.button("Confirm"):
                user["pw_hash"] = hashlib.sha256(new_pw.encode()).hexdigest()
                save_user(user)
                st.success("Password changed")
                st.rerun()

        if st.button("Generate New Keypair"):
            if st.checkbox("Old chats will be lost"):
                keys = sc.gen_keys()
                keys["pub_hex"] = base64.b64decode(keys["pub"]).hex()
                user["keys"] = keys
                save_user(user)
                st.success("New keypair")
                st.rerun()

        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()