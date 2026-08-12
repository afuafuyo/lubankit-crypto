## Browser crypto

#### Usage

```javascript
import Crypto from '@lubankit/crypto';

const pwd = '123456'
const msg = 'hello world'

const encrypted = Crypto.encrypt(msg, pwd);

const decrypted = Crypto.decrypt(encrypted, pwd); // 'hello world'
```
