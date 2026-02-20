//! Pure SHA-256, HMAC-SHA256, and PBKDF2-HMAC-SHA256.

const K: [u32; 64] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H_INIT: [u32; 8] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const BLOCK_SIZE: usize = 64;

#[derive(Clone)]
pub struct Sha256 {
  state: [u32; 8],
  buf: [u8; BLOCK_SIZE],
  buf_len: usize,
  total: u64,
}

impl Sha256 {
  pub fn new() -> Self {
    Self { state: H_INIT, buf: [0; BLOCK_SIZE], buf_len: 0, total: 0 }
  }

  pub fn update(&mut self, data: &[u8]) {
    self.total += data.len() as u64;
    let mut off = 0;
    if self.buf_len > 0 {
      let need = BLOCK_SIZE - self.buf_len;
      if data.len() < need {
        self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
        self.buf_len += data.len();
        return;
      }
      self.buf[self.buf_len..BLOCK_SIZE].copy_from_slice(&data[..need]);
      let block = self.buf;
      compress(&mut self.state, &block);
      self.buf_len = 0;
      off = need;
    }
    while off + BLOCK_SIZE <= data.len() {
      let mut block = [0u8; BLOCK_SIZE];
      block.copy_from_slice(&data[off..off + BLOCK_SIZE]);
      compress(&mut self.state, &block);
      off += BLOCK_SIZE;
    }
    let rem = data.len() - off;
    if rem > 0 {
      self.buf[..rem].copy_from_slice(&data[off..]);
      self.buf_len = rem;
    }
  }

  pub fn finalize(mut self) -> [u8; 32] {
    let bit_len = self.total * 8;
    // Append 0x80
    self.buf[self.buf_len] = 0x80;
    self.buf_len += 1;
    if self.buf_len > 56 {
      // Not enough room for length; pad this block, compress, start new block
      for i in self.buf_len..BLOCK_SIZE {
        self.buf[i] = 0;
      }
      let block = self.buf;
      compress(&mut self.state, &block);
      self.buf_len = 0;
    }
    for i in self.buf_len..56 {
      self.buf[i] = 0;
    }
    self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
    let block = self.buf;
    compress(&mut self.state, &block);

    let mut out = [0u8; 32];
    for (i, &w) in self.state.iter().enumerate() {
      out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
  }

  pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut h = Self::new();
    h.update(data);
    h.finalize()
  }
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
  let mut w = [0u32; 64];
  for i in 0..16 {
    w[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
  }
  for i in 16..64 {
    let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
    let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
  }

  let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
  for i in 0..64 {
    let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
    let ch = (e & f) ^ (!e & g);
    let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
    let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    let t2 = s0.wrapping_add(maj);
    h = g;
    g = f;
    f = e;
    e = d.wrapping_add(t1);
    d = c;
    c = b;
    b = a;
    a = t1.wrapping_add(t2);
  }

  state[0] = state[0].wrapping_add(a);
  state[1] = state[1].wrapping_add(b);
  state[2] = state[2].wrapping_add(c);
  state[3] = state[3].wrapping_add(d);
  state[4] = state[4].wrapping_add(e);
  state[5] = state[5].wrapping_add(f);
  state[6] = state[6].wrapping_add(g);
  state[7] = state[7].wrapping_add(h);
}

// --- HMAC-SHA256 ---

#[derive(Clone)]
pub struct HmacSha256 {
  inner: Sha256,
  outer: Sha256,
}

impl HmacSha256 {
  pub fn new(key: &[u8]) -> Self {
    let mut k = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
      k[..32].copy_from_slice(&Sha256::hash(key));
    } else {
      k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
      ipad[i] ^= k[i];
      opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    let mut outer = Sha256::new();
    outer.update(&opad);
    Self { inner, outer }
  }

  pub fn update(&mut self, data: &[u8]) {
    self.inner.update(data);
  }

  pub fn finalize(self) -> [u8; 32] {
    let inner_hash = self.inner.finalize();
    let mut outer = self.outer;
    outer.update(&inner_hash);
    outer.finalize()
  }

  pub fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Self::new(key);
    h.update(data);
    h.finalize()
  }
}

// --- PBKDF2-HMAC-SHA256 ---

pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
  let mut block_num = 1u32;
  let mut off = 0;
  while off < out.len() {
    let mut u = {
      let mut h = HmacSha256::new(password);
      h.update(salt);
      h.update(&block_num.to_be_bytes());
      h.finalize()
    };
    let mut t = u;
    for _ in 1..iterations {
      u = HmacSha256::mac(password, &u);
      for (a, &b) in t.iter_mut().zip(u.iter()) {
        *a ^= b;
      }
    }
    let take = (out.len() - off).min(32);
    out[off..off + take].copy_from_slice(&t[..take]);
    off += take;
    block_num += 1;
  }
}
