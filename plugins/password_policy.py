#!/usr/bin/python3

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, Tuple, List

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItem, QFont
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QFormLayout, QCheckBox, QSpinBox, QLabel,
    QHBoxLayout, QPushButton, QMessageBox, QStackedWidget, QListWidget,
    QListWidgetItem, QGroupBox
)

import plugins
from my_utils import check_package_installed


# Пути
APP_ROOT = Path(__file__).resolve().parents[1]
RES_DIR = APP_ROOT / "res"
DEFAULTS_YML = RES_DIR / "password_policy.yml"

PAM_DIR = Path("/etc/pam.d")
PAM_PASSWD = PAM_DIR / "passwd"
PASSWDQC_CONF = Path("/etc/passwdqc.conf")
PWQ_BASE = Path("/etc/security/pwquality.conf")
PWQ_D_DIR = Path("/etc/security/pwquality.conf.d")
PWQ_D_OUR = PWQ_D_DIR / "90-protection-alt.conf"

PAM_MARK_BEGIN = "# Managed by Protection ALT GUI (begin)"
PAM_MARK_END = "# Managed by Protection ALT GUI (end)"


class PasswordWidget(QWidget):
    def __init__(self, palette=None):
        super().__init__()
        if palette: self.setPalette(palette)
        self._module_kind = self._detect_module()  # 'pwquality'|'passwdqc'|'none'
        self._pol_dir = Path("/etc/security/protection-alt")
        self._pol_file = self._pol_dir / "password_policies.yml"
        self._group_state: Dict[str, Dict[str, Any]] = {}     # имя_группы|"*ALL*" -> настройки
        self._active_group: str | None = None                 # текущая группа в форме
        self._build_ui()
        self._reload_groups()
        self._load()
        self._update_controls_enabled()

    # графика
    def _build_ui(self):
        v = QVBoxLayout(self)

        top = QHBoxLayout()
        self.btn_enable_pwq = QPushButton(self.tr("Install/enable pam_pwquality"))
        top.addWidget(self.btn_enable_pwq); top.addStretch(1)
        v.addLayout(top)

        v.addWidget(QLabel(self.tr("Groups to which the policy applies:")))
        self.list_groups = QListWidget(); self.list_groups.setSelectionMode(QListWidget.MultiSelection)
        v.addWidget(self.list_groups, 1)
        self.lbl_active = QLabel(self.tr("Active group: —"))
        f = QFont(); f.setBold(True); self.lbl_active.setFont(f)
        v.addWidget(self.lbl_active)

        form = QFormLayout()
        self.sp_min = QSpinBox(); self.sp_min.setRange(4,128); self.sp_min.setKeyboardTracking(False); self.sp_min.setAccelerated(True)
        self.sp_difok = QSpinBox(); self.sp_difok.setRange(0,128); self.sp_difok.setKeyboardTracking(False)
        self.sp_l = QSpinBox(); self.sp_l.setRange(0,16); self.sp_l.setKeyboardTracking(False)
        self.sp_u = QSpinBox(); self.sp_u.setRange(0,16); self.sp_u.setKeyboardTracking(False)
        self.sp_d = QSpinBox(); self.sp_d.setRange(0,16); self.sp_d.setKeyboardTracking(False)
        self.sp_o = QSpinBox(); self.sp_o.setRange(0,16); self.sp_o.setKeyboardTracking(False)
        self.sp_remember = QSpinBox(); self.sp_remember.setRange(1,10); self.sp_remember.setKeyboardTracking(False)
        self.sp_retry = QSpinBox(); self.sp_retry.setRange(2,5); self.sp_retry.setKeyboardTracking(False)

        self.chk_user = QCheckBox(self.tr("Check username"))
        self.chk_gecos = QCheckBox(self.tr("Check GECOS"))
        self.chk_dict = QCheckBox(self.tr("Dictionary check"))
        self.chk_root = QCheckBox(self.tr("Enforce for root"))

        form.addRow(self.tr("Minimum password length"), self.sp_min)
        form.addRow(self.tr("Minimum changed characters"), self.sp_difok)
        form.addRow(self.tr("Minimum lowercase"), self.sp_l)
        form.addRow(self.tr("Minimum uppercase"), self.sp_u)
        form.addRow(self.tr("Minimum digits"), self.sp_d)
        form.addRow(self.tr("Minimum other characters"), self.sp_o)
        form.addRow(self.tr("Password input attempts (retry)"), self.sp_retry)
        form.addRow(self.tr("Forbid reuse of last N passwords"), self.sp_remember)
        form.addRow(self.chk_user)
        form.addRow(self.chk_gecos)
        form.addRow(self.chk_dict)
        form.addRow(self.chk_root)
        v.addLayout(form)

        btns = QHBoxLayout()
        self.btn_apply = QPushButton(self.tr("Apply"))
        self.btn_reset = QPushButton(self.tr("Reset"))
        btns.addWidget(self.btn_apply); btns.addWidget(self.btn_reset); btns.addStretch(1)
        v.addLayout(btns)

        self.btn_enable_pwq.clicked.connect(self._on_enable_pwquality)
        self.btn_apply.clicked.connect(self._on_apply)
        self.btn_reset.clicked.connect(self._on_reset)
        self.list_groups.itemSelectionChanged.connect(self._on_groups_selection_changed)
        

    def _is_root(self) -> bool:
        try: return os.geteuid() == 0
        except Exception: return False

    def _detect_module(self) -> str:
        files = []
        if PAM_PASSWD.exists(): files.append(PAM_PASSWD)
        files += sorted(PAM_DIR.glob("system-auth*"))
        def has(p: Path, needle: str) -> bool:
            try:
                with p.open("r", encoding="utf-8", errors="ignore") as f:
                    return any(needle in ln for ln in f)
            except Exception:
                return False
        if any(has(p, "pam_pwquality.so") for p in files): return "pwquality"
        if any(has(p, "pam_passwdqc.so") for p in files): return "passwdqc"
        return "none"

    def _read_defaults_yml(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if not DEFAULTS_YML.exists(): return d
        try:
            import yaml
            with DEFAULTS_YML.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                if isinstance(data, dict): d = data
        except Exception:
            with DEFAULTS_YML.open("r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#") or ":" not in s: continue
                    k, v = s.split(":", 1); d[k.strip()] = v.strip()
        return d

    def _pam_read_pwquality_opts(self) -> Dict[str, str]:
        opts: Dict[str, str] = {}
        p = PAM_DIR / "system-auth.protection-alt"
        if not p.exists():
            return opts
        try:
            text = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return opts

        for ln in text:
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            if "pam_pwquality.so" not in s:
                continue
            parts = s.split()
            try:
                i = parts.index("pam_pwquality.so")
            except ValueError:
                i = None
                for j, t in enumerate(parts):
                    if t.endswith("pam_pwquality.so"):
                        i = j
                        break
                if i is None:
                    continue
            for tok in parts[i + 1:]:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    opts[k.strip()] = v.strip()
            break
        return opts

    def _pwq_read(self) -> Dict[str, str]:
        cfg: Dict[str, str] = {}
        def parse(p: Path):
            if not p.exists(): return
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s=line.strip()
                    if not s or s.startswith("#"): continue
                    if "=" in s:
                        k,v=s.split("=",1); cfg[k.strip()]=v.strip()
        parse(PWQ_BASE)
        if PWQ_D_DIR.exists():
            for p in sorted(PWQ_D_DIR.glob("*.conf")): parse(p)
        return cfg

    def _qc_read(self) -> Dict[str, str]:
        cfg: Dict[str, str] = {}
        if not PASSWDQC_CONF.exists(): return cfg
        with PASSWDQC_CONF.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s=line.strip()
                if not s or s.startswith("#"): continue
                if "=" in s:
                    k,v=s.split("=",1); cfg[k.strip()]=v.strip()
        return cfg

    def _qc_read_min(self) -> int:
        raw = self._qc_read().get("min","")
        try:
            parts=[int(x.strip()) for x in raw.split(",")]
            return min(parts) if len(parts)==5 else 8
        except Exception:
            return 8

    def _policies_read(self) -> Dict[str, Dict[str, Any]]:
        data: Dict[str, Dict[str, Any]] = {}
        if not self._pol_file.exists(): return data
        try:
            import yaml
            with self._pol_file.open("r", encoding="utf-8") as f:
                obj = yaml.safe_load(f) or {}
                if isinstance(obj, dict):
                    for k,v in obj.items():
                        if isinstance(v, dict): data[str(k)] = v
        except Exception:
            try:
                import json
                with self._pol_file.open("r", encoding="utf-8") as f:
                    obj = json.load(f)
                    if isinstance(obj, dict):
                        for k,v in obj.items():
                            if isinstance(v, dict): data[str(k)] = v
            except Exception:
                pass
        return data

    def _policies_write(self, mp: Dict[str, Dict[str, Any]]) -> None:
        try: self._pol_dir.mkdir(parents=True, exist_ok=True)
        except Exception: pass
        try:
            import yaml
            with self._pol_file.open("w", encoding="utf-8") as f:
                yaml.safe_dump(mp, f, allow_unicode=True, sort_keys=True)
            return
        except Exception:
            pass
        try:
            import json
            with self._pol_file.open("w", encoding="utf-8") as f:
                json.dump(mp, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _pwq_args_from_state(self, st: Dict[str, Any]) -> str:
        args = [
            f"retry={int(st.get('retry', 3))}",
            f"minlen={int(st.get('minlen', 8))}",
            f"difok={int(st.get('difok', 3))}",
            f"lcredit={-abs(int(st.get('req_l', 0)))}",
            f"ucredit={-abs(int(st.get('req_u', 0)))}",
            f"dcredit={-abs(int(st.get('req_d', 0)))}",
            f"ocredit={-abs(int(st.get('req_o', 0)))}",
            f"usercheck={1 if st.get('usercheck', True) else 0}",
            f"gecoscheck={1 if st.get('gecoscheck', True) else 0}",
            f"dictcheck={1 if st.get('dictcheck', True) else 0}",
            f"enforce_for_root={1 if st.get('root_enforce', False) else 0}",
        ]
        return " ".join(args)

    def _ensure_pwq_enforcing(self) -> Path:
        target = PWQ_D_OUR if PWQ_D_DIR.exists() else PWQ_BASE
        try:
            if target == PWQ_BASE and target.exists():
                shutil.copy2(target, target.with_suffix(".bak"))
        except Exception:
            pass
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as f:
            f.write("# Managed by Protection ALT GUI (pwquality)\n"
                    "enforcing=1\n")
        return target

    def _pam_render_block(self, states: Dict[str, Dict[str, Any]], sel_groups: List[str]) -> str:
        lines = [PAM_MARK_BEGIN]
        def sal_opts() -> List[str]:
            p = PAM_DIR / "system-auth-local-only"
            try:
                t = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                t = []
            for ln in t:
                s = ln.strip()
                if not s or s.startswith("#"): continue
                m = re.match(r'^\s*password\s+\S+\s+\S+\s+pam_tcb\.so\b(.*)$', s, flags=re.IGNORECASE)
                if m:
                    tail = (m.group(1) or "").strip()
                    opts = tail.split() if tail else []
                    if "use_authtok" not in opts:
                        opts = ["use_authtok"] + opts
                    return opts
            return ["use_authtok", "shadow", "fork", "nullok", "write_to=tcb"]

        def add_pair(st: Dict[str, Any]):
            lines.append(f"password   requisite                     pam_pwquality.so {self._pwq_args_from_state(st)}")
            lines.append("password   requisite                     pam_pwhistory.so use_authtok remember={r} enforce_for_root".format(r=int(st.get('remember',5))))

        if "*ALL*" in sel_groups or not sel_groups:
            add_pair(states.get("*ALL*", {}))
        else:
            for g in sorted(set(sel_groups)):
                lines.append(f"password   [success=2 default=ignore]   pam_succeed_if.so user notingroup {g}")
                add_pair(states.get(g, {}))

        lines.append("password        required                  pam_tcb.so " + " ".join(sal_opts()))
        lines.append(PAM_MARK_END)
        return "\n".join(lines) + "\n"

    def _pam_strip_legacy_quality_lines(self, text: str) -> str:
        begin = re.escape(PAM_MARK_BEGIN); end = re.escape(PAM_MARK_END)
        parts = []; pos = 0
        for m in re.finditer(rf"{begin}.*?{end}\n?", text, flags=re.DOTALL):
            parts.append(("outside", text[pos:m.start()]))
            parts.append(("inside", text[m.start():m.end()]))
            pos = m.end()
        parts.append(("outside", text[pos:]))

        def cleanse(chunk: str) -> str:
            out = []
            for ln in chunk.splitlines():
                s = ln.strip()
                if re.search(r"\bpam_pwquality\.so\b", s): continue
                if re.search(r"\bpam_passwdqc\.so\b", s): continue
                if re.search(r"\bpam_pwhistory\.so\b", s): continue
                out.append(ln)
            return "\n".join(out)

        rebuilt = []
        for kind, chunk in parts:
            rebuilt.append(chunk if kind=="inside" else cleanse(chunk))
        return re.sub(r"\n{3,}", "\n\n", "\n".join(rebuilt))

    def _pam_install_block(self, block_text: str) -> bool:
        prot_inc = PAM_DIR / "system-auth.protection-alt"
        try:
            if prot_inc.exists():
                shutil.copy2(prot_inc, prot_inc.with_suffix(".bak"))
        except Exception:
            pass
        try:
            with prot_inc.open("w", encoding="utf-8") as f:
                f.write(block_text)
        except Exception:
            return False

        try:
            sec = Path("/etc/security")
            sec.mkdir(mode=0o755, exist_ok=True)
            op = sec / "opasswd"
            if not op.exists():
                with open(op, "x", encoding="utf-8"): pass
            try: os.chown(op, 0, 0)
            except Exception: pass
            os.chmod(op, 0o600)
        except Exception:
            pass

        if not PAM_PASSWD.exists(): return False
        try:
            orig = PAM_PASSWD.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return False

        base = re.sub(
            rf"{re.escape(PAM_MARK_BEGIN)}.*?{re.escape(PAM_MARK_END)}\n?",
            "",
            orig, flags=re.DOTALL
        )

        lines = base.splitlines()
        pat_sys  = re.compile(r'^\s*password\s+include\s+system-auth(?:\s+.*)?$', re.IGNORECASE)
        pat_prot = re.compile(r'^\s*password\s+include\s+system-auth\.protection-alt(?:\s+.*)?$', re.IGNORECASE)
        pat_unix = re.compile(r'^\s*password\s+\S+\s+pam_unix\.so\b', re.IGNORECASE)
        pat_tcb  = re.compile(r'^\s*password\s+\S+\s+pam_tcb\.so\b', re.IGNORECASE)

        new_lines: List[str] = []
        have_prot = False
        for s in lines:
            if pat_unix.match(s):  continue
            if pat_tcb.match(s):   continue
            if pat_sys.match(s):
                new_lines.append("password        include         system-auth.protection-alt")
                have_prot = True
                continue
            if pat_prot.match(s):
                if not have_prot:
                    new_lines.append("password        include         system-auth.protection-alt")
                    have_prot = True
                continue
            new_lines.append(s)

        if not have_prot:
            ins = []
            inserted = False
            for s in new_lines:
                if (not inserted) and s.strip().lower().startswith("session"):
                    ins.append("password        include         system-auth.protection-alt")
                    inserted = True
                ins.append(s)
            if not inserted:
                ins.append("password        include         system-auth.protection-alt")
            new_lines = ins

        try:
            shutil.copy2(PAM_PASSWD, PAM_PASSWD.with_suffix(".bak.pam"))
        except Exception:
            pass
        try:
            text = "\n".join(new_lines) + "\n"
            text = re.sub(r"\n{3,}", "\n\n", text)
            PAM_PASSWD.write_text(text, encoding="utf-8")
            return True
        except Exception:
            return False

    # группы
    def _gid_min(self) -> int:
        try:
            with open("/etc/login.defs", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"): continue
                    if s.upper().startswith("GID_MIN"):
                        parts = s.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            return int(parts[1])
        except Exception:
            pass
        return 1000

    def _list_groups_all(self) -> List[Tuple[str, int]]:
        groups: List[Tuple[str, int]] = []
        try:
            with open("/etc/group", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s=line.strip()
                    if not s or s.startswith("#"): continue
                    parts = s.split(":")
                    if len(parts) >= 3 and parts[2].isdigit():
                        name = parts[0]; gid = int(parts[2])
                        groups.append((name, gid))
        except Exception:
            pass
        return groups

    def _all_non_system_group_names(self) -> List[str]:
        gid_min = self._gid_min()
        return [name for name, gid in self._list_groups_all() if gid >= gid_min]

    def _reload_groups(self):
        self.list_groups.clear()
        gid_min = self._gid_min()

        it_all = QListWidgetItem(self.tr("All groups"))
        it_all.setData(Qt.UserRole, "__ALL__")
        self.list_groups.addItem(it_all)

        for name, gid in sorted(self._list_groups_all(), key=lambda t: (t[1], t[0])):
            if gid < gid_min: continue
            it = QListWidgetItem(f"{name} (gid {gid})"); it.setData(Qt.UserRole, name)
            self.list_groups.addItem(it)

        self._active_group = "*ALL*"
        self.lbl_active.setText(self.tr("Active group: All groups"))
        self.list_groups.item(0).setSelected(True)

    def _selected_groups(self) -> List[str]:
        sel = [it.data(Qt.UserRole) for it in self.list_groups.selectedItems()]
        if "__ALL__" in sel: return ["*ALL*"]
        return [x for x in sel if x and x != "__ALL__"]

    def _state_from_form(self) -> Dict[str, Any]:
        return {
            "minlen": self.sp_min.value(),
            "difok": self.sp_difok.value(),
            "req_l": self.sp_l.value(),
            "req_u": self.sp_u.value(),
            "req_d": self.sp_d.value(),
            "req_o": self.sp_o.value(),
            "retry": self.sp_retry.value(),
            "remember": self.sp_remember.value(),
            "usercheck": self.chk_user.isChecked(),
            "gecoscheck": self.chk_gecos.isChecked(),
            "dictcheck": self.chk_dict.isChecked(),
            "root_enforce": self.chk_root.isChecked(),
        }

    def _apply_state_to_form(self, st: Dict[str, Any]):
        self.sp_min.setValue(int(st.get("minlen", self.sp_min.value())))
        self.sp_difok.setValue(int(st.get("difok", self.sp_difok.value())))
        self.sp_l.setValue(int(st.get("req_l", self.sp_l.value())))
        self.sp_u.setValue(int(st.get("req_u", self.sp_u.value())))
        self.sp_d.setValue(int(st.get("req_d", self.sp_d.value())))
        self.sp_o.setValue(int(st.get("req_o", self.sp_o.value())))
        self.sp_retry.setValue(int(st.get("retry", self.sp_retry.value())))
        self.sp_remember.setValue(int(st.get("remember", self.sp_remember.value())))
        self.chk_user.setChecked(bool(st.get("usercheck", self.chk_user.isChecked())))
        self.chk_gecos.setChecked(bool(st.get("gecoscheck", self.chk_gecos.isChecked())))
        self.chk_dict.setChecked(bool(st.get("dictcheck", self.chk_dict.isChecked())))
        self.chk_root.setChecked(bool(st.get("root_enforce", self.chk_root.isChecked())))

    def _on_groups_selection_changed(self):
        if self._active_group:
            self._group_state[self._active_group] = self._state_from_form()

        items = self.list_groups.selectedItems()
        if not items:
            self._active_group = None
            self.lbl_active.setText(self.tr("Active group: —"))
            return
        last = items[-1]
        key = last.data(Qt.UserRole)
        self._active_group = "*ALL*" if key == "__ALL__" else str(key)
        self.lbl_active.setText(self.tr("Active group: ") + (self.tr("All groups") if self._active_group=="*ALL*" else self._active_group))

        st = self._group_state.get(self._active_group)
        if st is None:
            st = dict(self._group_state.get("*ALL*", self._state_from_form()))
            self._group_state[self._active_group] = st
        self._apply_state_to_form(st)

    def _update_controls_enabled(self):
        have_mod = (self._module_kind in ("pwquality","passwdqc"))
        for w in (self.sp_difok, self.sp_l, self.sp_u, self.sp_d, self.sp_o,
                self.sp_retry,
                self.chk_user, self.chk_gecos, self.chk_dict, self.chk_root,
                self.sp_remember, self.list_groups):
            w.setEnabled(have_mod)
        self.btn_enable_pwq.setVisible(not have_mod)

    def _load(self):
        retry_now = 3
        try:
            pam_opts = self._pam_read_pwquality_opts()
            if "retry" in pam_opts:
                retry_now = int(pam_opts["retry"])
        except Exception:
            retry_now = 3

        if self._module_kind == "pwquality":
            cfg = self._pwq_read()
            def gi(name, d):
                try: return int(cfg.get(name, str(d)))
                except Exception: return d
            self.sp_min.setValue(gi("minlen",8))
            self.sp_difok.setValue(gi("difok",3))
            def req(v):
                try: x=int(v); return abs(x) if x<0 else 0
                except Exception: return 0
            self.sp_l.setValue(req(cfg.get("lcredit","0")))
            self.sp_u.setValue(req(cfg.get("ucredit","0")))
            self.sp_d.setValue(req(cfg.get("dcredit","0")))
            self.sp_o.setValue(req(cfg.get("ocredit","0")))
            self.chk_user.setChecked(gi("usercheck",1)!=0)
            self.chk_gecos.setChecked(gi("gecoscheck",1)!=0)
            self.chk_dict.setChecked(gi("dictcheck",1)!=0)
            self.chk_root.setChecked(gi("enforce_for_root",0)!=0)
        else:
            self.sp_min.setValue(self._qc_read_min())

        self.sp_retry.setValue(max(2, min(5, int(retry_now))))

        d = self._read_defaults_yml()
        try:
            r = int(d.get("history_remember", 5))
            self.sp_remember.setValue(max(1, min(10, r)))
        except Exception:
            self.sp_remember.setValue(5)

        self._group_state = self._policies_read()
        if "*ALL*" not in self._group_state:
            self._group_state["*ALL*"] = self._state_from_form()

        base_all = dict(self._group_state["*ALL*"])
        for g in self._all_non_system_group_names():
            self._group_state.setdefault(g, dict(base_all))

        self._apply_state_to_form(self._group_state["*ALL*"])

    def _validate(self) -> Tuple[bool, str]:
        if self.sp_min.value() < 6:
            return False, self.tr("Minimum length less than 6 is unsafe.")
        if self._module_kind == "pwquality":
            req_sum = self.sp_l.value()+self.sp_u.value()+self.sp_d.value()+self.sp_o.value()
            if req_sum > self.sp_min.value():
                return False, self.tr("Sum of required character classes exceeds the minimum length.")
            if self.sp_difok.value() > self.sp_min.value():
                return False, self.tr("“Minimum changed characters” exceeds the minimum length")
        sel = self._selected_groups()
        if not sel:
            return False, self.tr("No groups selected.")
        return True, ""

    def _install_pwquality_pkgs(self) -> bool:
        try:
            env = os.environ.copy(); env["DEBIAN_FRONTEND"]="noninteractive"
            subprocess.run(["apt-get","update"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
            subprocess.run(["apt-get","install","-y","libpwquality"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        except Exception:
            return False
        return check_package_installed("libpwquality")

    def _on_enable_pwquality(self):
        if not self._is_root():
            QMessageBox.warning(self, "pam_pwquality", self.tr("Root privileges (pkexec) are required for installation and configuration."))
            return
        installed = check_package_installed("libpwquality")
        if not installed:
            ret = QMessageBox.question(
                self, self.tr("pam_pwquality installation"),
                self.tr("pam_pwquality is required to enforce character class requirements.\nInstall libpwquality packages?"),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            if ret != QMessageBox.Yes:
                return
            if not self._install_pwquality_pkgs():
                QMessageBox.critical(self, self.tr("Installation"), self.tr("Failed to install packages. Check Internet/repositories."))
                return
        self._module_kind = "pwquality"
        self._update_controls_enabled()
        self._load()
        QMessageBox.information(self, self.tr("Done"), self.tr("pam_pwquality is ready. Set group parameters and apply."))

    def _on_apply(self):
        if not self._is_root():
            QMessageBox.critical(self, self.tr("Error"), self.tr("Insufficient privileges. Run via pkexec."))
            return
        ok, msg = self._validate()
        if not ok:
            QMessageBox.warning(self, self.tr("Parameter validation"), msg); return
        try:
            if self._active_group:
                self._group_state[self._active_group] = self._state_from_form()

            sel = self._selected_groups()

            if "*ALL*" in sel:
                st_all = dict(self._group_state.get("*ALL*", self._state_from_form()))
                for g in self._all_non_system_group_names():
                    self._group_state[g] = dict(st_all)

            states: Dict[str, Dict[str, Any]] = {}
            if "*ALL*" in sel:
                states["*ALL*"] = self._group_state.get("*ALL*", self._state_from_form())
            else:
                for g in sel:
                    states[g] = self._group_state.get(g, self._state_from_form())

            if self._module_kind == "pwquality":
                self._ensure_pwq_enforcing()

            block = self._pam_render_block(states, sel)
            if not self._pam_install_block(block):
                QMessageBox.critical(self, "PAM", self.tr("Failed to update /etc/pam.d/passwd.")); return

            self._policies_write(self._group_state)

            QMessageBox.information(self, self.tr("Done"), self.tr("Settings applied."))
        except Exception as e:
            QMessageBox.critical(self, self.tr("Error"), self.tr("Failed to apply: ") + str(e))

    def _on_reset(self):
        d = self._read_defaults_yml()
        def gi(key, default):
            v = d.get(key, default)
            try: return int(v) if isinstance(v,(int,str)) else default
            except Exception: return default
        def gb(key, default):
            v = d.get(key, default)
            if isinstance(v,bool): return v
            if isinstance(v,str): return v.lower() in ("1","true","yes","on")
            return default

        if self._active_group:
            st = {
                "minlen": gi("minlen", 8),
                "difok": gi("difok", 3),
                "req_l": gi("req_l", 0),
                "req_u": gi("req_u", 0),
                "req_d": gi("req_d", 0),
                "req_o": gi("req_o", 0),
                "retry": gi("retry", 3),
                "remember": gi("history_remember", 5),
                "usercheck": gb("usercheck", True),
                "gecoscheck": gb("gecoscheck", True),
                "dictcheck": gb("dictcheck", True),
                "root_enforce": gb("root_enforce", False),
            }
            self._group_state[self._active_group] = st
            self._apply_state_to_form(st)

        ok, msg = self._validate()
        if not ok:
            QMessageBox.warning(self, self.tr("Reset — parameter validation"), msg); return
        try:
            sel = self._selected_groups()

            if "*ALL*" in sel:
                st_all = dict(self._group_state.get("*ALL*", self._state_from_form()))
                for g in self._all_non_system_group_names():
                    self._group_state[g] = dict(st_all)

            states: Dict[str, Dict[str, Any]] = {}
            if "*ALL*" in sel:
                states["*ALL*"] = self._group_state["*ALL*"]
            else:
                for g in sel:
                    states[g] = self._group_state[g]

            if self._module_kind == "pwquality":
                self._ensure_pwq_enforcing()

            block = self._pam_render_block(states, sel)
            if not self._pam_install_block(block):
                QMessageBox.critical(self, self.tr("Reset"), self.tr("Failed to update /etc/pam.d/passwd.")); return

            self._policies_write(self._group_state)
            QMessageBox.information(self, self.tr("Reset"), self.tr("Values restored and applied."))
        except Exception as e:
            QMessageBox.critical(self, self.tr("Reset"), self.tr("Failed to apply values: ") + str(e))


class PasswordPlugin(plugins.Base):
    def __init__(self, plist=None, pane: QStackedWidget = None):
        super().__init__("password_policy", 20, plist, pane)
        if self.plist is not None and self.pane is not None:
            node = QStandardItem(self.tr("Password parameters"))
            node.setData(self.name)
            self.plist.appendRow([node])
            self.pane.addWidget(QWidget())

    def _do_start(self, idx: int):
        main_palette = self.pane.window().palette()
        self.pane.insertWidget(idx, PasswordWidget(main_palette))
