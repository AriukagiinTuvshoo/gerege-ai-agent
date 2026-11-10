# Omnichannel AI Chatbot Agent (Бүртгэл & Борлуулалтын Систем)

Энэхүү систем нь уламжлалт сарын хураамжтай платформуудыг (ManyChat, Chatfuel г.м) бүрэн орлох, **100% таны өөрийн эзэмшлийн (Vendor Lock-in байхгүй), сарын суурь төлбөргүй** AI чатбот платформ юм.

---

## 🌟 Гол давуу талууд
1. **Хэрэглээгээрээ тооцоо хийнэ**: Сарын суурь төлбөр 0₮. Google Gemini Flash (Free Tier) ашигладаг тул өдөр тутам бүрэн үнэгүй ашиглах боломжтой.
2. **Өгөгдөл таны мэдэлд үлдэнэ**: Бүртгэгдсэн бүх харилцагчийн нэр, утас, чат баазад хадгалагдаж, нэг товшилтоор **Excel (.CSV)** болгон татаж авна.
3. **Omnichannel холболт**: Нэг л AI агент таны **Facebook Page**, **Instagram Direct**, **Telegram Bot**, болон **Вэбсайт**-аар нэгэн зэрэг харилцаж бүртгэл авна.

---

## 🚀 Ажиллуулах заавар

### 1. Сервер эхлүүлэх
Сервер одоо шууд ажиллаж байна:
👉 Хөтөч (Browser) дээрээ **`http://localhost:8000`** хаягийг нээнэ үү.

*(Дараа нь дахин ажиллуулахдаа уг хавтсанд байгаа `start.bat` файлыг дарахад л хангалттай).*

---

### 2. Google Gemini API Түлхүүр оруулах (Үнэгүй)
1. [Google AI Studio (https://aistudio.google.com/app/apikey)](https://aistudio.google.com/app/apikey) руу Google хаягаараа нэвтэрч **"Create API key"** дарна.
2. Гарч ирсэн түлхүүрээ:
   * Вэб самбар дээрх **"Тохиргоо & Түлхүүр"** товчийг дараад оруулах
   * Эсвэл төслийн `.env` файлын `GEMINI_API_KEY=` ард бичээд хадгалахад л хангалттай!

---

### 3. Facebook Messenger & Instagram DM-тэй холбох

Facebook болон Instagram-д Webhook холбохын тулд серверийг нийтийн `https://` хаягтай болгох хэрэгтэй.

#### А. Түр туршихдаа (ngrok эсвэл Cloudflare Tunnel):
```bash
ngrok http 8000
```
Гарч ирсэн `https://xxxx.ngrok-free.app` хаягийг ашиглана.

#### Б. Meta for Developers дээр тохируулах:
1. [Meta for Developers](https://developers.facebook.com/) руу орж шинэ App үүсгэнэ.
2. **Messenger** болон **Instagram Graph API** бүтээгдэхүүнийг нэмнэ.
3. **Webhooks** тохиргоо руу орж:
   * **Callback URL**: `https://xxxx.ngrok-free.app/webhook`
   * **Verify Token**: `agent_verify_secret_token_123`
4. Шалгаад баталгаажсаны дараа **`messages`** болон **`messaging_postbacks`** эрхийг Subscribe хийнэ.
5. Хуудасны **Page Access Token**-оо аваад `.env` файл дахь `META_PAGE_ACCESS_TOKEN=` дээр тавина.

Одоо таны Facebook хуудас болон Instagram руу хэрэглэгч бичих үед энэхүү AI агент автоматаар найрсаг хариулж, дугаарыг нь бүртгэн авна!
