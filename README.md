# ShareazaParser

Script to parse Shareaza's "dat" files.
This scripts needs python version >= 3.5

## Usage
```sh
python ShareazaParser.py [-h] [-l level] [-c] [-s]
```
- -h: print this help and exits
- -c: output text to stdout
- -l level  (--level=level):
   Choose output level (only valid for text output):
   
     0 - Very Important: Only very important information is displayed
     
     1 - Important: Important information and level 0 information is displayed
     
     2 - Useful: Useful information and level 1 information is displayed
     
     3 - Debug(default): All available information is displayed
     
- -s: generate csv spreadsheet (instead of text)

 Timestamps are exported as Unix epoch in text files, or as Excel date in csv files.
