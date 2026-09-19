#!/usr/bin/env python3
import base64

CHUNKS = [
'I3c6XX9wWfM3J3p3HrszeDslO/d1fHJPpIiKzwyKk4GZsEyPql2K11jMwcSP7UyPj9nf/h3JFsTNGQ1GAswB+ITHQNBCEk1Me4UP/EjR/QjEHEDSikwFRVld6cHQ000RtdzVElWIko3fjt3Px12e7Z2dy4Wd+ZHTSxkQhpWc59EQAhURERhXX0kXOhkERMFVa10UV9UVVo',
'sfB2IiIh9XH2d7O69HCz/nQ6v72/r/4sr7u8O3ht/jg/uSpraL6tPur/v3r9/zZ4eeQlI6Uj9PRg5+EnJnW0NSf057Ak5KGnJm+hIyNi5OPmvH8uLi8v4evt7ak6fa/sryk7ZPv7P2jou+x7aGsqbCnXVRPEk5QSV9WDEcaSlRJQWxORVNJQFsOWVFERgYHFER7OXg9Y3t2f2Z9d3phPWhnYXlyU2thZm50anhCY2QvLhoeGh0lARkQVk9QHRASGl8xSU9ACAYQKwgAAUgKEg4GKj8/Pn8tfiIleiwzMDooOmptOG1xNSc6ZyV9ISwpMCfd1M+V1cHU3s7d9dvS2dPW24eNz8nPwoOAlMeM2sDAlbrz/vjwv6n0s/rs+PKi+PXzpdPaz63rre7s+Mr7/vTgloSEntDcl4+dn9DS2oXT2oGVh43Ti4aPlo2HipHEiIO3vvC2p6G7vriQsLK7tPG77r246OSlobmjoO+rsa+pu1xeWR8cSUwXTFAQE0YUFBkQ==',
'y8/RxsDJ7tzP9vi2/7yi5PjrvPSq8P/47+bu5fij6+bv9u3n6vrA6O+WnpWK1ZnBlZidhJuRmIPQjISIndOKxp6SlIyAwo2Plbq+vOK596Gjp723/q64ubutp6z0qeexs7etp+OurrqrXV0DWBRATEZeVhlPW1hUXERNFgYQDxdEAkZHS01UaX9fXSYxPCJkeGs+dCpwf3hvZm5leCRmcGtvfWxCamFobBcIVl8RFgQXHh9QVUkSXgAQDVQdUQpEBgcH',
'DhNYTwELMyI+NzUgOHguOT01b38xOyMyLiclMChtOTEtOyR8ayfP3NLF1cHQ1NyTj9CcyMTOxs2WhtjH3M7Sx8fEmcXF1/f7qPj04fHgq6Ou5/v45fiysLGw8P+97+Lv4er1vb2yxYiaxJiWgZ+ZgsnFxYHUnIeFiZzV1dHd39Da2Nvb1tCys7qxtauwpL+y6vi5urr58a7gprexq66ogKCiq6TrqxgBVVJSckBUX0RwXUtJU1dBWAYLQkdWW0xNTgIJSVNBd2l+eH8xfDFtaXtuMnEofCdhZXdsPWNiKiVlcnJiKXsDBRBbSkNWFRsBDlddCRkHER4KXkkFAxMMCQ0RDRJODjowIzk2NiE8fXY4OCY7PDY8Ij9lKy0lOCQpKzohaz8718XV49/AzZfVnMzWy8WRztPy3svOx9DEid3Dy8zI1Yu6vrL38+f98r395/375fL866mq8Pbm9a72vObt6vHo7JeO0pSClZGPnrSck5qSmYrExJSOk5WHn4qPwMXbksuTv7Wku+q68a+zrKLssf29oraupaWPramuo+yw5fuy7rdfVVJSTx0eDklBQkpQX1hPRk5FWAJMUElIZ0RDTkJJSjQzfnZuYzw3aHl9bXd0NWsofXV4JXFoZW19YScidSB7WEYUEgQcHV8CVl0GGhIVVAYeAgIeCwsCSRFCHBoIGBAtMHMocyE9LiNxdCdxeCU3LShnIzknITMkJiFmJmc7M9HAkcuJ0dLKn/f0/u7ez',
]

CHUNK_ORDER = [0, 2, 3, 1]
REVERSE_FLAGS = [1, 0, 0, 0]
XOR_KEY = ((0xD8 ^ 0x28) ^ (0xD0 ^ 0x12))  # 50
ROT_BITS = (0xD9 ^ 0xDD)                   # 04

parts = []
for idx in CHUNK_ORDER:
    chunk = CHUNKS[idx]
    if REVERSE_FLAGS[idx]:
        chunk = chunk[::-1]
    parts.append(chunk)
b64_blob = "".join(parts)
raw = base64.b64decode(b64_blob)

out = []
for i, byte in enumerate(raw):
    rotated = ((byte >> ROT_BITS) | (byte << (8 - ROT_BITS))) & 0xFF
    decrypted = rotated ^ XOR_KEY ^ (i & 0xFF)
    out.append(chr(decrypted))

payload = "".join(out)
print(payload)
