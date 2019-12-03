// Sample rule to match binaries over 100kb in size

rule matchover100kb {
	meta:
		score = 10
	condition:
		filesize > 100KB
}
