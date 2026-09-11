# Snare 🚀

> **QA muhandislari, backend va mobil dasturchilar uchun qulay, vizual HTTP/HTTPS tarmoq tahlilchisi va API Mock vositasi.**

Snare — bu **PySide6 (Qt)** va **mitmproxy** dvigateli asosida yaratilgan zamonaviy desktop ilovadir. U brauzerlar, kompyuter dasturlari hamda mobil ilovalar (iOS / Android) trafigini real vaqt rejimida ushlab qolish, tahlil qilish va eng muhimi — server javoblarini vizual tarzda **Mock (o‘zgartirish)** qilish imkonini beradi.

---

## 🤖 AI Hamkorligida Yaratilgan (Built with AI)

Ushbu loyiha zamonaviy dasturlash yondashuvlaridan foydalangan holda, **Antigravity (Google DeepMind)** sun'iy intellekt agenti va inson muhandisligining uzviy hamkorligida ishlab chiqildi. Arxitektura, asinxron jarayonlarni boshqarish, xavfsizlik filtrlari va qulay foydalanuvchi interfeysi (UI) AI ko‘magida bosqichma-bosqich optimallashtirilgan.

---

## ✨ Asosiy Imkoniyatlar

- 🌐 **Jonli Trafikni Kuzatish (Live Inspection):**
  - Barcha HTTP/HTTPS so‘rov va javoblarini real vaqtda ko‘rish.
  - Sarlavhalar (Headers), holat kodlari (Status), URL parametrlari va formatlangan JSON tana qismlari (Body).
  - Qulay JSON sintaksis bo‘yash (Highlighter) va bir bosishda nusxalash (Clipboard).

- 🎭 **Vizual Mock Qoidalar (Visual Mock Rules):**
  - **Local (Mahalliy javob):** Haqiqiy serverga bormasdan, dasturning o‘zidan istalgan status va JSON javob qaytarish.
  - **Patch (Server javobini o‘zgartirish):** Haqiqiy serverdan qaytgan ma'lumotning faqat ma'lum bir qismini (masalan, foydalanuvchi balansi yoki statusini) o‘zgartirib telefonga uzatish.
  - **Request Patch:** Telefon yoki brauzerdan serverga ketayotgan so‘rovni yo‘lda o‘zgartirish.
  - **Replace (To‘liq almashtirish):** Server javobini bekor qilib, o‘rniga yangi matn yoki fayl (Binary Fixture) qaytarish.

- 📱 **Mobil Qurilmalarni Ulash (Telefon / LAN):**
  - Bitta Wi-Fi tarmog‘idagi telefonlar trafigini ko‘rish uchun proksini bir bosishda butun tarmoqqa ochish (`0.0.0.0`).
  - Dastur ichida o‘rnatilgan qulay qo‘llanma va SSL sertifikatini (`http://mitm.it`) o‘rnatish ko‘rsatmalari.

- ⚡ **Windows Tizim Proksisi (System Proxy):**
  - Windows sozlamalaridagi proksini bir tugma bilan yoqish va o‘chirish.
  - Ilova yopilganda tizim sozlamalarini avtomatik ravishda asl holiga xavfsiz qaytarish (internet uzilib qolmaydi).

- 🧠 **Kengaytirilgan Shartlar va Ssenariylar:**
  - Bir xil endpointga ega so‘rovlar (masalan `/rpc`) uchun Request Body ichidagi parametrlar bo‘yicha aniq filtrlash.
  - Ssenariylar (Stateful Mocking): birinchi urinishda `500 Server Error`, ikkinchisida `200 Success` qaytarish (Retry logikasini test qilish uchun).
  - Sun'iy tarmoq kechikishi (Network Delay ms) va maksimal ishlash soni (Max hits).

---

## 📦 O‘rnatish va Ishga Tushirish

### Talablar:
- **Python:** `>= 3.12`
- **Operatsion tizim:** Windows 10/11, macOS yoki Linux

### 1. Repozitoriyni yuklab oling:
```bash
git clone https://github.com/IamSodikov/snare.git
cd snare
```

### 2. Virtual muhit (venv) yarating va faollashtiring:
```powershell
# Virtual muhit yaratish
python -m venv venv

# Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# Linux yoki macOS:
source venv/bin/activate
```

### 3. Kutubxonalarni o‘rnating:
```bash
pip install -e .
```

### 4. Dasturni ishga tushiring:
```powershell
snare
# yoki
python -m desktop_sniffer
```

---

## 📱 Mobil Telefonni Ulash Bo‘yicha Qisqa Qo‘llanma

1. Ilova yuqorisidagi **"Telefon / LAN"** sozlamasini yoqing.
2. Tepadagi **"Mobile Setup"** tugmasini bosing va ko‘rsatilgan kompyuteringiz IP manzili va portini eslab qoling.
3. Telefoningizni kompyuter bilan **aynan bir xil Wi-Fi tarmog‘iga** ulang.
4. Telefoningizning Wi-Fi sozlamalariga kirib, proksi parametrlariga o‘sha IP va portni kiriting.
5. Telefon brauzeridan **`http://mitm.it`** saytiga kirib, o‘z tizimingizga mos (Android yoki iOS) sertifikatni yuklab oling va o‘rnating:
   * *iOS qurilmalarida:* Sozlamalar ➡️ Asosiy ➡️ Qurilma haqida ➡️ Sertifikatlarga ishonch sozlamalari bo‘limidan mitmproxy sertifikatini yoqib qo‘ying.
   * *Android qurilmalarida:* Xavfsizlik ➡️ CA sertifikatini o‘rnatish bo‘limidan yuklangan faylni tanlang.

---

## 🔒 Xavfsizlik va Maxfiylik

Ushbu dastur xavfsizlik standartlariga to‘liq javob beradi:
1. **Shaxsiy kalitlar (Private Keys):** `mitmproxy` generatsiya qilgan ildiz sertifikati kalitlari repozitoriyga kirmasligi uchun `.gitignore` orqali to‘liq himoyalangan.
2. **Ushlangan trafiklar (Tokens, Parollar, Ma'lumotlar):** Test jarayonida yozib olingan barcha ma'lumotlar loyiha papkasida emas, balki foydalanuvchining shaxsiy tizim papkasida saqlanadi (`%APPDATA%\LocalTools\DesktopSniffer\workspaces\`). Git orqali hech qanday shaxsiy trafik tashqariga chiqib ketmaydi.
3. **Avtomatik tozalash:** Dastur yopilayotganda barcha jarayonlar xavfsiz to‘xtatiladi va Windows proksi sozlamalari zudlik bilan tiklanadi.

---

## ⚖️ Litsenziya

Ushbu loyiha **[MIT License](LICENSE)** asosida ochiq manbali qilib tarqatiladi.

Qo‘llanilgan asosiy vositalar litsenziyalari:
* **mitmproxy** — [MIT License](https://github.com/mitmproxy/mitmproxy/blob/main/LICENSE)
* **PySide6 (Qt)** — [LGPLv3](https://www.gnu.org/licenses/lgpl-3.0.html) (Dinamik import qilingani sababli loyihaning MIT litsenziyasiga to‘liq mos keladi).

---

## 🤝 Hamjamiyat va Hissa Qo‘shish (Contributing)

Loyiha bo‘yicha yangi takliflar, xatoliklar haqidagi xabarlar yoki pull request'lar doimo kutib olinadi!
Batafsil ma'lumot olish uchun **[CONTRIBUTING.md](CONTRIBUTING.md)** fayli bilan tanishib chiqing.

Dastur O‘zbekiston IT hamjamiyatiga foydali bo‘ladi degan umiddamiz! 🇺🇿
