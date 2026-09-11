"""spec 011a (RF-035) — SearchsploitParser + product_version. Unit, sin lanzar searchsploit."""
import json

from app.executors.searchsploit_executor import product_version
from app.parsers.searchsploit_parser import SearchsploitParser

_APACHE_JSON = json.dumps({
    "SEARCH": "apache 2.4.49",
    "RESULTS_EXPLOIT": [
        {
            "Title": "Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)",
            "EDB-ID": "50383",
            "Date_Published": "2021-10-07",
            "Path": "/usr/share/exploitdb/exploits/multiple/webapps/50383.sh",
        },
        {
            "Title": "Apache 2.4.49/2.4.50 - Path Traversal & RCE (mod_cgi)",
            "EDB-ID": "50406",
            "Date_Published": "2021-10-25",
            "Path": "/usr/share/exploitdb/exploits/multiple/webapps/50406.py",
        },
    ],
    "RESULTS_SHELLCODE": [],
    "RESULTS_PAPER": [],
})

_EMPTY_JSON = json.dumps({"SEARCH": "nginx 1.99", "RESULTS_EXPLOIT": []})


def _raw(s: str) -> dict:
    return {"tool": "searchsploit", "command": "searchsploit ...", "raw_output": s}


def test_parse_produce_un_finding_con_exploit_refs():
    findings = SearchsploitParser().parse(_raw(_APACHE_JSON))
    assert len(findings) == 1
    f = findings[0]
    assert "apache 2.4.49" in f["title"].lower()
    assert f["severity"].value == "info"
    ids = {r["id"] for r in f["exploit_refs"]}
    assert ids == {"50383", "50406"}
    assert all(r["db"] == "exploit-db" for r in f["exploit_refs"])
    assert all(r["url"] == f"https://www.exploit-db.com/exploits/{r['id']}" for r in f["exploit_refs"])


def test_parse_sin_resultados_no_produce_finding():
    assert SearchsploitParser().parse(_raw(_EMPTY_JSON)) == []
    assert SearchsploitParser().parse(_raw("")) == []
    assert SearchsploitParser().parse(_raw("not json")) == []


def test_product_version_desde_string():
    assert product_version("apache 2.4.49") == ("apache", "2.4.49")
    assert product_version("joomla 4.2.7") == ("joomla", "4.2.7")


def test_product_version_desde_cpe():
    p, v = product_version("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert p == "http server" and v == "2.4.49"


def test_product_version_sin_version_devuelve_vacio():
    assert product_version("joomla") == ("", "")
    assert product_version("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*") == ("", "")
