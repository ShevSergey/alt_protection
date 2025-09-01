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
        self.btn_enable_pwq = QPushButton(self.tr("Установить/включить pam_pwquality"))
        top.addWidget(self.btn_enable_pwq); top.addStretch(1)
        v.addLayout(top)

        v.addWidget(QLabel(self.tr("Группы, к которым применяется политика:")))
        self.list_groups = QListWidget(); self.list_groups.setSelectionMode(QListWidget.MultiSelection)
        v.addWidget(self.list_groups, 1)
        self.lbl_active = QLabel(self.tr("Активная группа: —"))
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
        self.chk_user = QCheckBox(self.tr("Проверка имени пользователя"))
        self.chk_gecos = QCheckBox(self.tr("Проверка GECOS"))
        self.chk_root = QCheckBox(self.tr("Применять для root"))

        form.addRow(self.tr("Минимальная длина пароля"), self.sp_min)
        form.addRow(self.tr("Минимум изменённых символов"), self.sp_difok)
        form.addRow(self.tr("Мин. строчных"), self.sp_l)
        form.addRow(self.tr("Мин. заглавных"), self.sp_u)
        form.addRow(self.tr("Мин. цифр"), self.sp_d)
        form.addRow(self.tr("Мин. других символов"), self.sp_o)
        form.addRow(self.tr("Запрет на повтор последних N паролей"), self.sp_remember)
        form.addRow(self.chk_user)
        form.addRow(self.chk_gecos)
        form.addRow(self.chk_root)
        v.addLayout(form)

        btns = QHBoxLayout()
        self.btn_apply = QPushButton(self.tr("Применить"))
        self.btn_reset = QPushButton(self.tr("Сбросить"))
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
            "retry=3",
            "try_first_pass",
            f"minlen={int(st.get('minlen', 8))}",
            f"difok={int(st.get('difok', 3))}",
            f"lcredit={-abs(int(st.get('req_l', 0)))}",
            f"ucredit={-abs(int(st.get('req_u', 0)))}",
            f"dcredit={-abs(int(st.get('req_d', 0)))}",
            f"ocredit={-abs(int(st.get('req_o', 0)))}",
            f"usercheck={1 if st.get('usercheck', True) else 0}",
            f"gecoscheck={1 if st.get('gecoscheck', True) else 0}",
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
        if not sel_groups: return ""
        lines = [PAM_MARK_BEGIN]

        def add_pair(st: Dict[str, Any]):
            # 1) качество
            if self._module_kind == "pwquality":
                lines.append(f"password   requisite                     pam_pwquality.so {self._pwq_args_from_state(st)}")
            else:
                cfg_path = str(PASSWDQC_CONF)
                lines.append(f"password   requisite                     pam_passwdqc.so config={cfg_path} retry=3")
            # 2) история
            lines.append(
                "password   requisite                     pam_pwhistory.so "
                f"use_authtok remember={int(st.get('remember',5))} enforce_for_root"
            )

        if "*ALL*" in sel_groups:
            st = states.get("*ALL*", {})
            add_pair(st)
        else:
            for g in sorted(set(sel_groups)):
                st = states.get(g, {})
                lines.append(f"password   [success=2 default=ignore]   pam_succeed_if.so user notingroup {g}")
                add_pair(st)

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
        base = self._pam_strip_legacy_quality_lines(base)

        lines = base.splitlines()

        idx_insert = -1
        pat_include = re.compile(r'^\s*password\s+include\s+system-auth\b')
        for i, ln in enumerate(lines):
            if pat_include.search(ln) or ("pam_tcb.so" in ln and ln.strip().startswith("password")):
                idx_insert = i; break

        out = []
        if idx_insert >= 0:
            out.extend(lines[:idx_insert])
            if block_text.strip():
                out.append(block_text.rstrip("\n"))
            out.append("password        required        pam_tcb.so use_authtok")
            out.extend(lines[idx_insert+1:])
        else:
            if block_text.strip():
                out = lines + ["", block_text.rstrip("\n"), "password        required        pam_tcb.so use_authtok"]
            else:
                out = lines + ["", "password        required        pam_tcb.so use_authtok"]

        try:
            shutil.copy2(PAM_PASSWD, PAM_PASSWD.with_suffix(".bak.pam"))
        except Exception:
            pass
        try:
            text = "\n".join(out) + "\n"
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

        it_all = QListWidgetItem(self.tr("Все группы"))
        it_all.setData(Qt.UserRole, "__ALL__")
        self.list_groups.addItem(it_all)

        for name, gid in sorted(self._list_groups_all(), key=lambda t: (t[1], t[0])):
            if gid < gid_min: continue
            it = QListWidgetItem(f"{name} (gid {gid})"); it.setData(Qt.UserRole, name)
            self.list_groups.addItem(it)

        self._active_group = "*ALL*"
        self.lbl_active.setText(self.tr("Активная группа: Все группы"))
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
            "remember": self.sp_remember.value(),
            "usercheck": self.chk_user.isChecked(),
            "gecoscheck": self.chk_gecos.isChecked(),
            "root_enforce": self.chk_root.isChecked(),
        }

    def _apply_state_to_form(self, st: Dict[str, Any]):
        self.sp_min.setValue(int(st.get("minlen", self.sp_min.value())))
        self.sp_difok.setValue(int(st.get("difok", self.sp_difok.value())))
        self.sp_l.setValue(int(st.get("req_l", self.sp_l.value())))
        self.sp_u.setValue(int(st.get("req_u", self.sp_u.value())))
        self.sp_d.setValue(int(st.get("req_d", self.sp_d.value())))
        self.sp_o.setValue(int(st.get("req_o", self.sp_o.value())))
        self.sp_remember.setValue(int(st.get("remember", self.sp_remember.value())))
        self.chk_user.setChecked(bool(st.get("usercheck", self.chk_user.isChecked())))
        self.chk_gecos.setChecked(bool(st.get("gecoscheck", self.chk_gecos.isChecked())))
        self.chk_root.setChecked(bool(st.get("root_enforce", self.chk_root.isChecked())))

    def _on_groups_selection_changed(self):
        if self._active_group:
            self._group_state[self._active_group] = self._state_from_form()

        items = self.list_groups.selectedItems()
        if not items:
            self._active_group = None
            self.lbl_active.setText(self.tr("Активная группа: —"))
            return
        last = items[-1]
        key = last.data(Qt.UserRole)
        self._active_group = "*ALL*" if key == "__ALL__" else str(key)
        self.lbl_active.setText(self.tr("Активная группа: ") + (self.tr("Все группы") if self._active_group=="*ALL*" else self._active_group))

        st = self._group_state.get(self._active_group)
        if st is None:
            st = dict(self._group_state.get("*ALL*", self._state_from_form()))
            self._group_state[self._active_group] = st
        self._apply_state_to_form(st)

    def _update_controls_enabled(self):
        have_mod = (self._module_kind in ("pwquality","passwdqc"))
        for w in (self.sp_difok, self.sp_l, self.sp_u, self.sp_d, self.sp_o,
                  self.chk_user, self.chk_gecos, self.chk_root,
                  self.sp_remember, self.list_groups):
            w.setEnabled(have_mod)
        self.btn_enable_pwq.setVisible(not have_mod)

    def _load(self):
        if self._module_kind == "pwquality":
            cfg = self._pwq_read()
            def gi(name,d):
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
            self.chk_root.setChecked(gi("enforce_for_root",0)!=0)
        else:
            self.sp_min.setValue(self._qc_read_min())

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
            return False, self.tr("Минимальная длина менее 6 небезопасна.")
        if self._module_kind == "pwquality":
            req_sum = self.sp_l.value()+self.sp_u.value()+self.sp_d.value()+self.sp_o.value()
            if req_sum > self.sp_min.value():
                return False, self.tr("Сумма минимальных классов больше минимальной длины.")
            if self.sp_difok.value() > self.sp_min.value():
                return False, self.tr("«Минимум изменённых символов» больше минимальной длины.")
        sel = self._selected_groups()
        if not sel:
            return False, self.tr("Не выбраны группы.")
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
            QMessageBox.warning(self, "pam_pwquality", self.tr("Нужны root-права (pkexec) для установки и настройки."))
            return
        installed = check_package_installed("libpwquality")
        if not installed:
            ret = QMessageBox.question(
                self, self.tr("Установка pam_pwquality"),
                self.tr("Для требований по классам символов нужен pam_pwquality.\nУстановить пакеты libpwquality?"),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            if ret != QMessageBox.Yes:
                return
            if not self._install_pwquality_pkgs():
                QMessageBox.critical(self, self.tr("Установка"), self.tr("Не удалось установить пакеты. Проверьте интернет/репозитории."))
                return
        self._module_kind = "pwquality"
        self._update_controls_enabled()
        self._load()
        QMessageBox.information(self, self.tr("Готово"), self.tr("pam_pwquality готов. Задайте параметры для группы и примените."))

    def _on_apply(self):
        if not self._is_root():
            QMessageBox.critical(self, self.tr("Ошибка"), self.tr("Недостаточно прав. Запустите через pkexec."))
            return
        ok, msg = self._validate()
        if not ok:
            QMessageBox.warning(self, self.tr("Проверка параметров"), msg); return
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
                QMessageBox.critical(self, "PAM", self.tr("Не удалось обновить /etc/pam.d/passwd.")); return

            self._policies_write(self._group_state)

            QMessageBox.information(self, self.tr("Готово"), self.tr("Настройки применены."))
        except Exception as e:
            QMessageBox.critical(self, self.tr("Ошибка"), self.tr("Не удалось применить: ") + str(e))

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
                "remember": gi("history_remember", 5),
                "usercheck": gb("usercheck", True),
                "gecoscheck": gb("gecoscheck", True),
                "root_enforce": gb("root_enforce", False),
            }
            self._group_state[self._active_group] = st
            self._apply_state_to_form(st)

        ok, msg = self._validate()
        if not ok:
            QMessageBox.warning(self, self.tr("Сброс — проверка параметров"), msg); return
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
                QMessageBox.critical(self, self.tr("Сброс"), self.tr("Не удалось обновить /etc/pam.d/passwd.")); return

            self._policies_write(self._group_state)
            QMessageBox.information(self, self.tr("Сброс"), self.tr("Значения восстановлены и применены."))
        except Exception as e:
            QMessageBox.critical(self, self.tr("Сброс"), self.tr("Не удалось применить значения: ") + str(e))


class PasswordPlugin(plugins.Base):
    def __init__(self, plist=None, pane: QStackedWidget = None):
        super().__init__("password_policy", 20, plist, pane)
        if self.plist is not None and self.pane is not None:
            node = QStandardItem(self.tr("Параметры пароля"))
            node.setData(self.name)
            self.plist.appendRow([node])
            self.pane.addWidget(QWidget())

    def _do_start(self, idx: int):
        main_palette = self.pane.window().palette()
        self.pane.insertWidget(idx, PasswordWidget(main_palette))
