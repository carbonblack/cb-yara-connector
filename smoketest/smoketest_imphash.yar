import "pe"

rule matchover100kb {
        meta:
                score = 10
        condition:
                pe.imphash()=="1dfcf659cd022725d2a87599a5697d53"
}
