|  JSON Field Name |  Artifact Class Property |  Data Type / Enum Conversion | Purpose in SOC Case Builder |
|---|---|---|---|
|  case_id | self.case_id  | str  | Groups related artifacts into their respective security investigation cases.  |
| indicator_type  |  self.indicator_type |  ArtifactType (Enum) |  Categorizes the artifact into structured types (IP, DOMAIN, FILE_HASH, UNKNOWN) via ArtifactType.from_str(). |
| domain  |  self.domain | str  | Stores the parsed domain name value.  |
| ip  | self.ip  | str  | Stores the parsed network IP address.  |
| file_hash  |  self.file_hash | str  |  Stores the parsed cryptographic file signature/hash string. |
| comment  |  self.comment | str  |  Captures contextual analyst notes or training description details. |