from .sqli import run_sqli_attack
from .auth import run_password_length, run_replay_attack
from .traffic import run_traffic_spike
from .data import run_malformed_json
from .idor import run_idor_attack
from .rce import run_rce_attack
from .jwt_weakness import run_jwt_attack
from .ssrf import run_ssrf_attack
from .lfi import run_lfi_attack
from .nosql import run_nosql_attack
from .ssti import run_ssti_attack
from .crash import run_xml_bomb, run_redos, run_huge_json
from .web_exploits import run_prototype_pollution, run_xss_scan, run_open_redirect
from .injection_exotic import run_shellshock, run_ldap_injection
from .cve_classics import run_log4j_attack, run_spring4shell, run_struts2_rce
from .infra import run_http_desync
from .dos_extreme import run_slowloris, run_large_payload, run_header_bomb
from .config_exposure import run_debug_exposure, run_secret_leak
from .file_upload import run_file_upload_abuse, run_zip_slip
from .logic import run_race_condition, run_otp_reuse
from .deserialization import run_insecure_deserialization, run_yaml_abuse
from .headers import run_header_security_check
from .crlf import run_crlf_injection
from .xxe import run_xxe_exfil
from .brute import run_brute_force

ATTACK_DISPATCHER = {
    # ... Previous ...
    "sql_injection": run_sqli_attack,
    "blind_sqli": run_sqli_attack, 
    "time_sqli": run_sqli_attack,
    "nosql_injection": run_nosql_attack,
    "rce": run_rce_attack,
    "ssti": run_ssti_attack,
    "ldap_injection": run_ldap_injection,
    "shellshock": run_shellshock,
    "log4shell": run_log4j_attack,
    "spring4shell": run_spring4shell,
    "struts2_rce": run_struts2_rce,
    "lfi": run_lfi_attack,
    "path_traversal": run_lfi_attack,
    "file_upload_abuse": run_file_upload_abuse,
    "zip_slip": run_zip_slip,
    "idor": run_idor_attack,
    "jwt_weakness": run_jwt_attack,
    "password_length": run_password_length,
    "otp_reuse": run_otp_reuse,
    "xss": run_xss_scan,
    "open_redirect": run_open_redirect,
    "prototype_pollution": run_prototype_pollution,
    "ssrf": run_ssrf_attack,
    "xml_bomb": run_xml_bomb,
    "json_bomb": run_huge_json,
    "insecure_deserialization": run_insecure_deserialization,
    "yaml_abuse": run_yaml_abuse,
    "replay_attack": run_replay_attack,
    "race_condition": run_race_condition,
    "traffic_spike": run_traffic_spike,
    "slowloris": run_slowloris,
    "body_bomb": run_large_payload,
    "header_bomb": run_header_bomb,
    "redos": run_redos,
    "http_desync": run_http_desync,
    "debug_exposure": run_debug_exposure,
    "secret_leak": run_secret_leak,
    
    # NEW
    "header_security": run_header_security_check,
    "crlf_injection": run_crlf_injection,
    "xxe_exfil": run_xxe_exfil,
    "brute_force": run_brute_force
}

# Metadata registry for scoring
ATTACK_METADATA = {
    "sql_injection": {"severity": "critical"},
    "rce": {"severity": "critical"},
    "log4shell": {"severity": "critical"},
    "slowloris": {"severity": "high"},
    "xxe_exfil": {"severity": "critical"},
    "crlf_injection": {"severity": "medium"},
    "header_security": {"severity": "low"},
    "brute_force": {"severity": "high"},
    "debug_exposure": {"severity": "medium"}
}
