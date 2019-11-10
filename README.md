# p0f-log-analyzer
a simple python script to analyze p0f logs

usage
```sh
python p0f-log-analyzer.py <path to log>
```


example output (of a single IP, blurred out)
```
{
    "184.105.xxx.xxx": {
        "first_seen": "2019/11/10 08:49:57",
        "last_seen": "2019/11/10 08:49:57",
        "links": [
            "Ethernet or modem"
        ],
        "mtus": [
            "1500"
        ],
        "os_matches": [
            "Linux 2.2.x-3.x"
        ],
        "raw_freqs": [
            "252.38 Hz"
        ],
        "types": [
            "cli"
        ],
        "uptimes": [
            "15 days 12 hrs 44 min (modulo 198 days)"
        ]
    }
}
```
