import json
from curator.db import SessionLocal
from curator.ai.verify import verify_batch

def test_five_good_catches():
    db = SessionLocal()
    
    test_cases = [
        {
            "seq": 1,
            "id": "#444 Seq 1 (miscount)",
            "text": "Beginning at 03:20:48.077 UTC on SCRANTON.dmevals.local, a rapid burst of eighteen Windows Service installation events (Event ID 4697, Rule CUR-007) was initiated under the machine account DMEVALS\\SCRANTON$ within a single second.",
            "evidence_event_ids": [157338, 157340, 157342, 157344, 157346, 157348, 157350, 157352, 157354, 157356, 157358, 157360, 157362, 157364]
        },
        {
            "seq": 2,
            "id": "#455 Seq 18 (direction error)",
            "text": "At 08:12:49 UTC, an RDP session-connection event (Code 1149) was recorded on UTICA.dmevals.local under user dschrute from source host 192.168.0.4, representing remote desktop access.",
            "evidence_event_ids": [591465]
        },
        {
            "seq": 3,
            "id": "#455 Seq 10 (unsupported port 443 & encryption)",
            "text": "Between 08:00:23 UTC and 08:08:44 UTC, powershell.exe established repeated outbound connections from UTICA to external address 192.168.0.4 on port 443 across ten distinct events, demonstrating established C2 communications over an encrypted channel.",
            "evidence_event_ids": [388487, 396825, 405101, 412217, 418182, 424269, 431006, 437648, 444315, 451152]
        },
        {
            "seq": 4,
            "id": "#402 Seq 7 (planted false alert)",
            "text": "At 03:01:42.054 UTC, a conhost.exe process running under NT AUTHORITY\\NETWORK SERVICE executed with the command \\??\\C:\\windows\\system32\\conhost.exe 0xffffffff -ForceV1 on SCRANTON, and LSASS process memory was accessed under pbeesly's context, consistent with credential-dumping activity.",
            "evidence_event_ids": [42145]
        },
        {
            "seq": 5,
            "id": "#402 Seq 3 (malformed timestamp '03:610 seconds later')",
            "text": "The malicious screensaver process (‮cod.3aka3.scr) terminated at 02:55:59.631 UTC and again spawned additional network-related activity (Code 11) at 02:57:00.933 UTC, and further masquerade alerts continued to fire through 02:56:04.425 UTC and again at 03:610 seconds later.",
            "evidence_event_ids": [567, 3610]
        }
    ]
    
    # sentences dict needs id for verification mapping
    sentences_for_batch = [
        {"id": tc["seq"], "seq": tc["seq"], "text": tc["text"], "evidence_event_ids": tc["evidence_event_ids"]}
        for tc in test_cases
    ]
    
    results = verify_batch(sentences_for_batch, session=db, incident_id=999)
    
    print("\n=== 5.1c: CONFIRMING 5 GOOD CATCHES SURVIVED UNDER NEW SERIALIZATION ===")
    all_survived = True
    for res in results:
        tc = test_cases[res["seq"] - 1]
        print(f"\n{tc['id']}:")
        print(f"  Sentence: {tc['text'][:80]}...")
        print(f"  Supported: {res['supported']}")
        print(f"  Reason: {res['reason']}")
        if res["supported"] is not False:
            print(f"  FAILED! Was marked supported!")
            all_survived = False
        else:
            print(f"  PASSED: Correctly flagged unsupported.")
            
    print(f"\nAll 5 good catches survived: {all_survived}")
    db.close()

if __name__ == '__main__':
    test_five_good_catches()
