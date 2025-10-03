# [DumpMe](https://cyberdefenders.org/blueteam-ctf-challenges/dumpme/)

## Scenario

A SOC analyst took a memory dump from a machine infected with a meterpreter malware. As a Digital Forensicators, your job is to analyze the dump, extract the available indicators of compromise (IOCs) and answer the provided questions.

## Questions

1. What is the SHA1 hash of Triage-Memory.mem (memory dump)?
1. What volatility profile is the most appropriate for this machine? (ex: Win10x86_14393)
1. What was the process ID of notepad.exe?
1. Name the child process of wscript.exe?
1. What was the IP address of the machine at the time the RAM dump was created?
1. Based on the answer regarding the infected PID, can you determine the IP of the attacker?
1. How many processes are associated with VCRUNTIME140.dll?
1. After dumping the infected process, what is its md5 hash?
1. What is the LM hash of Bob's account?
1. What memory protection constants does the VAD node at 0xfffffa800577ba10 have?
1. What memory protection did the VAD starting at 0x00000000033c0000 and ending at 0x00000000033dffff have?
1. There was a VBS script that ran on the machine. What is the name of the script? (submit without file extension)
1. An application was run at 2019-03-07 23:06:58 UTC. What is the name of the program? (Include extension)
1. What was written in notepad.exe at the time when the memory dump was captured?
1. What is the short name of the file at file record 59045?
1. This box was exploited and is running meterpreter. What was the infected PID?

## Analysis

We are provided with a MEM file called `Triage-Memory.mem`. In the first question we are asked to provide the SHA1 hash of this file.

### 1. What is the SHA1 hash of Triage-Memory.mem (memory dump)?

We can use the `sha1sum` tool to calculate the hash of the file. The tool returns the value described below:

```
┌──(cyberseclabunix㉿cyberseclabunix)-[~/Documents/temp_extract_dir]
└─$ sha1sum Triage-Memory.mem 

c95e8cc8c946f95a109ea8e47a6800de10a27abd  Triage-Memory.mem
```

### 2. What volatility profile is the most appropriate for this machine? (ex: Win10x86_14393)

We need to find out the most appropriate volatility profile. Since there has been a mention of meterpreter usage, we can consider running a `windows.info` module in `volatility`.

In Volatility 2 there is a module called `imageinfo` we can use to determine the answer to this question.

![](1.png)

We take the first value from the left and it seems to be the correct answer: "Win7SP1x64".

### 3. What was the process ID of notepad.exe?

The process can be looked up via the `pslist` module. Since we know that profile to use, we will specify it as well using `--profile=Win7SP1x64`. 

```
┌──(cyberseclabunix㉿cyberseclabunix)-[~/volatility]
└─$ python2 vol.py pslist -f ~/Documents/temp_extract_dir/Triage-Memory.mem --profile=Win7SP1x64 | grep notepad

Volatility Foundation Volatility Framework 2.6.1
0xfffffa80054f9060 notepad.exe            3032   1432      1       60      1      0 2019-03-22 05:32:22 UTC+0000
```

We can determine that the process ID we've been asked to find is `3032`.

### 4. Name the child process of wscript.exe?

Getting the parent and child processes is easy. There is a `pstree` module that will output all processes in a tree format.

![](2.png)

From the screenshot we can see that the `wscript.exe` process is a parent to a `UWkpjFjDzM.exe` process, which is at least suspicious looking.

### 5. What was the IP address of the machine at the time the RAM dump was created?

For that question I tried modules `connections`, `connscan` and `sockscan` but all of them are not supported for the Win7SP1 profile. One specific module has worked, `netscan`.

Running the line below has revealed all active connections:

```log
$ python2 vol.py netscan --profile=Win7SP1x64 -f ~/Documents/temp_extract_dir/Triage-Memory.mem
```

We got a lot of entries, and after a quick analysis we can see that one address keeps popping up as the local address: `10.0.0.101`. Windows by default use NetBIOS services running on port 137 using the local IPv4 address that we want.

I'll filter out all other connections via `grep` command.

![](3.png)

Looks like this is the answer we were looking for.

### 6. Based on the answer regarding the infected PID, can you determine the IP of the attacker?

All there is to do is to filter this connection list by the infected process name `UWkpjFjDzM.exe`.

![](4.png)

Since there is mention of meterpreter usage, it is probably a reverse shell session, where the victim starts the connection to the attacker, that has an open port running. The screenshot above depicts such behavior. The attacker's IP address is `10.0.0.106`.

### 7. How many processes are associated with VCRUNTIME140.dll?

> [!WARNING]
> Work in progress

## Answers

1. What is the SHA1 hash of Triage-Memory.mem (memory dump)?

> `c95e8cc8c946f95a109ea8e47a6800de10a27abd`

1. What volatility profile is the most appropriate for this machine? (ex: Win10x86_14393)

> `Win7SP1x64`

1. What was the process ID of notepad.exe?

> `3032`

1. Name the child process of wscript.exe?

> `UWkpjFjDzM.exe`

1. What was the IP address of the machine at the time the RAM dump was created?

> `10.0.0.101`

1. Based on the answer regarding the infected PID, can you determine the IP of the attacker?

> `10.0.0.106`

1. How many processes are associated with VCRUNTIME140.dll?

> Answer

1. After dumping the infected process, what is its md5 hash?

> Answer

1. What is the LM hash of Bob's account?

> Answer

1. What memory protection constants does the VAD node at 0xfffffa800577ba10 have?

> Answer

1. What memory protection did the VAD starting at 0x00000000033c0000 and ending at 0x00000000033dffff have?

> Answer

1. There was a VBS script that ran on the machine. What is the name of the script? (submit without file extension)

> Answer

1. An application was run at 2019-03-07 23:06:58 UTC. What is the name of the program? (Include extension)

> Answer

1. What was written in notepad.exe at the time when the memory dump was captured?

> Answer

1. What is the short name of the file at file record 59045?

> Answer

1. This box was exploited and is running meterpreter. What was the infected PID?

> Answer

## Resources used

* Resource 1
* Resource 2
* Resource 3
