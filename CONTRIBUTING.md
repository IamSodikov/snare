# Loyihaga Hissa Qo‘shish (Contributing Guide)

Desktop Sniffer loyihasiga qiziqish bildirganingiz uchun tashakkur! Ushbu loyiha O‘zbekistonlik QA muhandislari va dasturchilarining kundalik ishini osonlashtirish maqsadida ochiq manbali qilib yaratilgan.

---

## 💡 Qanday qilib hissa qo‘shish mumkin?

### 1. Xatoliklar haqida xabar berish (Bug Reports)
Agar dasturda biror xatolik yoki kutilmagan to‘xtash yuz bersa, GitHub'dagi **Issues** bo‘limida yangi masala oching va quyidagilarni ilova qiling:
- Operatsion tizimingiz va versiyasi (Windows 10/11, macOS, Linux).
- Python versiyasi (`python --version`).
- Xatoni takrorlash bo‘yicha ketma-ket qadamlar.
- Ilovaning **Engine Logs** bo‘limidagi tegishli log yozuvlari.

### 2. Yangi imkoniyatlar taklif qilish (Feature Requests)
Agar dasturda qandaydir yangi qulaylik yoki funksiya bo‘lishini xohlasangiz, **Issues** bo‘limida taklif qoldiring va u nima uchun foydali bo‘lishini tushuntiring.

### 3. Kod orqali hissa qo‘shish (Pull Requests)
1. Repozitoriyni o‘z profilingizga **Fork** qiling.
2. Yangi tarmoq (branch) oching:
   ```bash
   git checkout -b feature/YangiQulaylik
   ```
3. O‘zgarishlarni kiriting va mavjud testlar muvaffaqiyatli o‘tayotganini tekshiring:
   ```bash
   pytest
   ```
4. Kod sifatini Ruff yordamida tekshiring:
   ```bash
   ruff check .
   ```
5. O‘zgarishlarni commit qilib, o‘z repozitoriyingizga push qiling:
   ```bash
   git commit -m "feat: Yangi qulaylik qo'shildi"
   git push origin feature/YangiQulaylik
   ```
6. Asosiy repozitoriyga **Pull Request (PR)** yuboring.

---

Har qanday yordam va takliflar uchun oldindan minnatdorchilik bildiramiz! 🤝
