# p0f-log-analyzer
a simple python script to analyze p0f logs

usage
```sh
python p0f-log-analyzer.py <path to log>
```


example output (of a single IP, blurred out)
```
{
        "distances": [
            "19"
        ],
        "first_seen": "2019/11/09 22:51:50",
        "ip": "177.38.xxx.xxx",
        "last_seen": "2019/11/09 22:54:19",
        "links": [
            "Ethernet or modem"
        ],
        "mtus": [
            "1500"
        ],
        "os_matches": [
            "Windows 7 or 8"
        ],
        "types": [
            "cli"
        ]
    }

```


using https://sqlify.io/ to convert the JSON output to SQLite/CSV works very well!

