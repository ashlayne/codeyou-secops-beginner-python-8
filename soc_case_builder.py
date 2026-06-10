def main():
	import requests
	import os

	#region API checker
	# API Key: cf7bbbd0

	API_URL = "https://my.api.mockaroo.com/ironclad-soc-case-artifacts"

	headers = {
		"X-API-Key": os.environ.get("MOCKAROO_API_KEY"),
		# "x-api-key": os.environ.get("MOCKAROO_API_KEY") 
		# # Backup for strict routing
		# # Helper for debugging
	}
	
	# api_key = os.environ.get("MOCKAROO_API_KEY")
	# print(f"DEBUG: API Key found in env is: {api_key}")
	# # helper for debugging

	response = requests.get(API_URL, headers=headers, timeout=10)
	print("Status: ", response.status_code)

	if response.status_code != 200:
		print("Request failed: ", response.text[:200])
		raise SystemExit
	
	data = response.json()
	print("JSON type:", type(data))
	print("Records:", len(data) if isinstance(data, list) else "N/A")
	#endregion

	#region Record Preview
	# Preview first record
	if isinstance(data, list) and data:
		print("First record preview:")
		print(data[0])
	else:
		print("Unexpected JSON structure. Expected a list of records.")
		raise SystemExit
	
	if isinstance(data[0], dict):
		print("\nFields in record:")
		for k in data[0].keys():
			print("-", k)
	#endregion

	from enum import Enum

	#region Enum classes
	class Severity(Enum):
		LOW = "LOW"
		MEDIUM = "MEDIUM"
		HIGH = "HIGH"

	class CaseStatus(Enum):
		NEW = "NEW"
		INVESTIGATING = "INVESTIGATING"
		RESOLVED = "RESOLVED"
		FALSE_POSITIVE = "FALSE_POSITIVE"

	class ArtifactType(Enum): #new Enum class for Challenge A
		DOMAIN = "DOMAIN"
		IP = "IP"
		FILE_HASH = "FILE_HASH"
		UNKNOWN = "UNKNOWN"

		@classmethod
		def from_str(cls, value: str):
			if not value:
				return cls.UNKNOWN
			
			clean_value = str(value).strip().upper()

			for member in cls:
				if member.value == clean_value:
					return member
					
			return cls.UNKNOWN

	#endregion

	#region Artifact class
	class Artifact:
		def __init__(self, raw: dict):
			
			self.raw = raw

			self.case_id = raw.get("case_id", "UNKNOWN_CASE")
			
			#region strings, no longer needed from Challenge A
			# self.indicator_type = raw.get("indicator_type", "unknown")
			# self.domain = raw.get("domain", "unknown domain")
			# self.ip = raw.get("ip", "unknown IP")
			# self.file_hash = raw.get("file_hash", "unknown hash")
			# self.comment = raw.get("comment", "no comment found")
			#endregion

			#region Enum conversion for Challenge A
			raw_type = raw.get("indicator_type", "unknown")
			self.indicator_type = ArtifactType.from_str(raw_type) 
			self.domain = raw.get("domain", "unknown domain")
			self.ip = raw.get("ip", "unknown IP")
			self.file_hash = raw.get("file_hash", "unknown hash")
			self.comment = raw.get("comment", "no comment found")
			#endregion

		def is_internal_ip(self) -> bool:
			# only relevant if indicator_type indicates an IP
			if self.indicator_type != ArtifactType.IP:
				return False
			return self.value.startswith(("10.", "192.168."))

		def __str__(self) -> str:
			extra = f" ({self.comment})" if self.comment else ""
			return f"{self.indicator_type.value}: {self.value}{extra}"
		
		@property
		def value(self):
			if self.indicator_type == ArtifactType.IP:
				return self.ip
			elif self.indicator_type == ArtifactType.DOMAIN:
				return self.domain
			elif self.indicator_type == ArtifactType.FILE_HASH:
				return self.file_hash
			return "Unknown Value"
	#endregion
		
	test_artifact = Artifact(data[0])
	print(test_artifact)
	# Testing Output

	#region class Case
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
			
			# HIGH if file hash present
			has_hash = any(a.indicator_type == ArtifactType.FILE_HASH for a in self.artifacts)
			# using new Enum ArtifactType for Challenge A
			if has_hash:
				self.severity = Severity.HIGH
				return
			
			# MEDIUM if any external IP or suspicious domain keyword
			has_external_ip = any(
				a.indicator_type == ArtifactType.IP and not a.is_internal_ip()
				# using new Enum ArtifactType for Challenge A
				for a in self.artifacts
			)
			has_suspicious_domain = any(
				a.indicator_type == ArtifactType.DOMAIN and any(word in a.value.lower() for word in ["login", "verify", "secure"])
				# using new Enum ArtifactType for Challenge A
				for a in self.artifacts
			)

			if has_external_ip or has_suspicious_domain:
				self.severity = Severity.MEDIUM
			
			# All other cases are LOW
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
	#endregion

	cases_by_id = {}

	for record in data:
		artifact = Artifact(record)

		if artifact.case_id not in cases_by_id:
			cases_by_id[artifact.case_id] = Case(artifact.case_id)

		cases_by_id[artifact.case_id].add_artifact(artifact)

	#region File outputs
	# print("\n=== Case Summaries ===")
	# for c in cases_by_id.values():
	# 	print(c.summary())
	# # Testing output

	# Map Severity enum to numeric weight for sorting - Challenge D
	severity_order = {
		Severity.HIGH: 1,
		Severity.MEDIUM: 2,
		Severity.LOW: 3
	}

	# Sort the cases using the mapping dictionary as the sorting key - Challenge D
	sorted_cases = sorted(
		cases_by_id.values(),
		key=lambda case: severity_order.get(case.severity, 4))

	with open("case_summary.txt", "w", encoding="utf-8") as out:
		for c in sorted_cases:
			out.write(str(c.summary()))
			out.write("\n")
	
	print("\nWrote summary to case_summary.txt")

	with open("case_report.txt", "w", encoding="utf-8") as out:
		for c in sorted_cases:
			out.write(str(c))
			out.write("\n\n")

	print("Wrote report to case_report.txt")
	#endregion

	# Challenge C - Deduped IOCs - extended to sort them by IOC type
	with open("unique_iocs.txt", "w", encoding="utf-8") as out:
		# Using a set comprehension to automatically extract and deduplicate values
		unique_iocs = {artifact.value for case in cases_by_id.values() for artifact in case.artifacts}

		for a_type in ArtifactType:
			if a_type == ArtifactType.UNKNOWN:
				continue
		
			iocs_by_type = {
				a.value for c in cases_by_id.values() for a in c.artifacts 
				if a.indicator_type == a_type
			}

			if iocs_by_type:
				out.write(f"\n[{a_type.value.upper()}s]\n")
				for ioc in sorted(iocs_by_type):
					out.write(f" - {ioc}\n")

		
		#region unsorted IOC output
		# for ioc in sorted(unique_iocs):
		# 	# Write unique IOCs to a file
		# 	out.write(str(ioc))
		# 	out.write("\n\n")
		#endregion

	print("Wrote unique Indicators of Compromise to unique_iocs.txt")

	
if __name__ == '__main__':
	main()	