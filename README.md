# 🐍 Python Assignment: SOC Case Builder (Classes + API + JSON)

## Introduction

In a SOC, data rarely arrives as clean text files. It usually comes from **APIs** (ticketing systems, alert platforms, threat feeds, or internal services). Analysts and engineers must pull that data, understand its structure, and model it in code.

In this assignment, you will pull “case artifact” data from a Mockaroo API endpoint, inspect the JSON structure, and build a small **case tracking model** using Python classes.

---

## Learning Objectives

You will learn to:

* Pull and parse JSON from an API using `requests`
* Inspect unfamiliar JSON and identify its fields
* Design a class (`Artifact`) that matches a real data structure
* Build a second class (`Case`) that *contains* artifacts (composition)
* Use enums for consistent severity and status
* Generate a formatted report file from class objects

---

## Provided Resource

👉 **Mockaroo API URL:** Refer to your classroom assignment for the URL and key.

> The API returns JSON records representing artifacts associated with cases.

---

# Part 1 — Walkthrough (Guided Build)

## Step 1: Fetch JSON from the API

Install requests if needed:

```bash
python -m pip install requests
export MOCKAROO_API_KEY="<insert the API Key from the classroom>"
```

Create `soc_case_builder.py`:

```python
import requests
import os

API_URL = "PASTE_YOUR_MOCKAROO_URL_HERE"

headers = {
    "X-API-Key": os.environ.get("MOCKAROO_API_KEY")
}

response = requests.get(API_URL, timeout=10)
print("Status:", response.status_code)

if response.status_code != 200:
    print("Request failed:", response.text[:200])
    raise SystemExit

data = response.json()
print("JSON type:", type(data))
print("Records:", len(data) if isinstance(data, list) else "N/A")

# Preview first record
if isinstance(data, list) and data:
    print("First record preview:")
    print(data[0])
else:
    print("Unexpected JSON structure. Expected a list of records.")
    raise SystemExit
```

✅ **Checkpoint:** You can see one record printed and understand what fields exist.

---

## Step 2: Inspect Fields and Write Them Down

Add this helper code:

```python
if isinstance(data[0], dict):
    print("\nFields in record:")
    for k in data[0].keys():
        print("-", k)
```

✅ **Student Task:** Copy the field names into your notes.
You will use those fields to design your `Artifact` class.

---

## Step 3: Create Enums for Severity and Status

Add:

```python
from enum import Enum

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class CaseStatus(Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
```

---

## Step 4: Build the `Artifact` Class (Student Must Design)

### Required: Your class must be based on your JSON fields.

At minimum, your `Artifact` object must capture:

* the case identifier (ex: `case_id`)
* artifact type (domain/ip/hash/etc.)
* artifact value
* an optional note/description (if present)
* (optional) timestamp, source, or severity fields if present in your JSON

### Example Template (Students Fill In)

```python
class Artifact:
    def __init__(self, raw: dict):
        self.raw = raw

        # TODO: Replace these keys with the actual JSON field names
        self.case_id = raw.get("case_id", "UNKNOWN_CASE")
        self.artifact_type = raw.get("artifact_type", "unknown")
        self.value = raw.get("value", "")
        self.note = raw.get("note", "")

    def is_internal_ip(self) -> bool:
        # only relevant if artifact_type indicates an IP
        if self.artifact_type != "ip":
            return False
        return self.value.startswith(("10.", "192.168."))

    def __str__(self) -> str:
        extra = f" ({self.note})" if self.note else ""
        return f"{self.artifact_type}: {self.value}{extra}"
```

✅ **Checkpoint:** Create one Artifact from `data[0]` and print it.

```python
test_artifact = Artifact(data[0])
print(test_artifact)
```

---

## Step 5: Build the `Case` Class (Composition)

```python
class Case:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.status = CaseStatus.NEW
        self.severity = Severity.LOW
        self.artifacts: list[Artifact] = []
        self.notes: list[str] = []

    def add_artifact(self, artifact: Artifact):
        self.artifacts.append(artifact)
        self.recalculate_severity()

    def add_note(self, note: str):
        self.notes.append(note)

    def recalculate_severity(self):
        # Simple rules (you may adjust based on your data):
        # HIGH if any file hash present
        # MEDIUM if any external IP or suspicious domain keyword
        # LOW otherwise

        has_hash = any(a.artifact_type in ["file_hash", "hash", "sha256"] for a in self.artifacts)
        if has_hash:
            self.severity = Severity.HIGH
            return

        has_external_ip = any(
            a.artifact_type == "ip" and not a.is_internal_ip()
            for a in self.artifacts
        )
        has_suspicious_domain = any(
            a.artifact_type == "domain" and any(word in a.value.lower() for word in ["login", "verify", "secure"])
            for a in self.artifacts
        )

        if has_external_ip or has_suspicious_domain:
            self.severity = Severity.MEDIUM
        else:
            self.severity = Severity.LOW

    def summary(self) -> str:
        return f"{self.case_id} | {self.status.value} | {self.severity.value} | artifacts={len(self.artifacts)}"

    def __str__(self) -> str:
        lines = [self.summary(), "-" * 48, "Artifacts:"]
        for a in self.artifacts:
            lines.append(f"  - {a}")
        if self.notes:
            lines.append("Notes:")
            for n in self.notes:
                lines.append(f"  * {n}")
        return "\n".join(lines)
```

---

## Step 6: Group Artifacts Into Cases

Create a dictionary: case_id → Case object.

```python
cases_by_id = {}

for record in data:
    artifact = Artifact(record)

    if artifact.case_id not in cases_by_id:
        cases_by_id[artifact.case_id] = Case(artifact.case_id)

    cases_by_id[artifact.case_id].add_artifact(artifact)
```

✅ **Checkpoint:**

```python
print("\n=== Case Summaries ===")
for c in cases_by_id.values():
    print(c.summary())
```

---

## Step 7: Write a Report File

```python
with open("case_report.txt", "w", encoding="utf-8") as out:
    for c in cases_by_id.values():
        out.write(str(c))
        out.write("\n\n")

print("\nWrote report to case_report.txt")
```

---

# Part 2 — Challenge (Pick 3)

## Challenge A: Add `ArtifactType` Enum

Create an enum for artifact types and convert raw strings into enum values.

## Challenge B: Add `Case.close()` Rule

If severity is HIGH, case cannot be closed directly → must go INVESTIGATING.

## Challenge C: Add `get_iocs()` Method

Return a deduplicated list of IOC values (domains, IPs, hashes).

## Challenge D: Sort Cases by Severity

Print cases in order: HIGH → MEDIUM → LOW.

## Challenge E: Add “Aging”

If your JSON includes a date/timestamp field, compute “days old” and list stale cases.

---

# 📦 Deliverables

Submit:

1. `soc_case_builder.py`
2. `case_report.txt`
3. Screenshot / pasted terminal output showing:

   * status code
   * first record preview
   * case summary output
4. Notes (short): list the JSON field names you discovered and how you mapped them into your `Artifact` class
5. 3 challenge items completed (state which)

---

# ✅ Rubric (50 points)

* API request + JSON parsing works (10)
* Student inspected fields and correctly mapped JSON → Artifact (10)
* `Artifact` class works (`__str__`, internal IP check) (10)
* Cases grouped correctly using `Case` class (10)
* Report generated correctly (5)
* Challenge work (5)

---

## 📚 References

* Requests quickstart: [https://requests.readthedocs.io/en/latest/user/quickstart/](https://requests.readthedocs.io/en/latest/user/quickstart/)
* Python dict `.get()`: [https://docs.python.org/3/tutorial/datastructures.html#dictionaries](https://docs.python.org/3/tutorial/datastructures.html#dictionaries)
* Enums: [https://docs.python.org/3/library/enum.html](https://docs.python.org/3/library/enum.html)
* Sorting: [https://docs.python.org/3/howto/sorting.html](https://docs.python.org/3/howto/sorting.html)
