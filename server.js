const express = require("express");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const PARTNER_ID = Number(process.env.SHOPEE_PARTNER_ID);
const PARTNER_KEY = process.env.SHOPEE_PARTNER_KEY;

let authState = {
  shopId: null,
  accessToken: null,
  refreshToken: null,
  expiresAt: null
};

app.use(express.json());

function gerarAssinatura(path, timestamp, accessToken, shopId) {
  const baseString =
    PARTNER_ID.toString() +
    path +
    timestamp.toString() +
    accessToken +
    shopId.toString();

  return crypto
    .createHmac("sha256", PARTNER_KEY)
    .update(baseString)
    .digest("hex");
}

app.get("/", (req, res) => {
  res.send("Shopee Review Bot online.");
});

app.get("/callback", async (req, res) => {
  try {
    const { code, shop_id } = req.query;

    if (!code || !shop_id) {
      return res.status(400).json({
        ok: false,
        message: "code ou shop_id não recebido."
      });
    }

    const path = "/api/v2/auth/token/get";
    const timestamp = Math.floor(Date.now() / 1000);

    const baseString =
      PARTNER_ID.toString() +
      path +
      timestamp.toString();

    const sign = crypto
      .createHmac("sha256", PARTNER_KEY)
      .update(baseString)
      .digest("hex");

    const url =
      `https://partner.shopeemobile.com${path}` +
      `?partner_id=${PARTNER_ID}` +
      `&timestamp=${timestamp}` +
      `&sign=${sign}`;

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        code,
        shop_id: Number(shop_id),
        partner_id: PARTNER_ID
      })
    });

    const data = await response.json();

    if (data.error) {
      console.error("Erro Shopee ao obter token:", data);

      return res.status(400).json({
        ok: false,
        shopee_error: data
      });
    }

    authState = {
      shopId: Number(shop_id),
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: Date.now() + data.expire_in * 1000
    };

    console.log("Token Shopee armazenado em memória.");
    console.log("Shop ID:", authState.shopId);

    return res.json({
      ok: true,
      message: "Token Shopee obtido e armazenado com sucesso.",
      shop_id: authState.shopId,
      access_token_received: Boolean(data.access_token),
      refresh_token_received: Boolean(data.refresh_token),
      expire_in: data.expire_in
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/auth/status", (req, res) => {
  res.json({
    authenticated: Boolean(authState.accessToken),
    shop_id: authState.shopId,
    token_valid:
      Boolean(authState.expiresAt) &&
      authState.expiresAt > Date.now()
  });
});

app.get("/reviews", async (req, res) => {
  try {
    if (!authState.accessToken || !authState.shopId) {
      return res.status(401).json({
        ok: false,
        message: "Loja ainda não autorizada nesta execução."
      });
    }

    if (authState.expiresAt <= Date.now()) {
      return res.status(401).json({
        ok: false,
        message: "Access token expirado."
      });
    }

    const path = "/api/v2/product/get_comment";
    const timestamp = Math.floor(Date.now() / 1000);

    const sign = gerarAssinatura(
      path,
      timestamp,
      authState.accessToken,
      authState.shopId
    );

    const url =
  `https://partner.shopeemobile.com${path}` +
  `?partner_id=${PARTNER_ID}` +
  `&timestamp=${timestamp}` +
  `&access_token=${authState.accessToken}` +
  `&shop_id=${authState.shopId}` +
  `&sign=${sign}` +
  `&page_size=20`;

    const response = await fetch(url);

    const data = await response.json();

    console.log("Resposta get_comment:");
    console.dir(data, { depth: null });

    return res.json({
      ok: !data.error,
      data
    });

  } catch (error) {
    console.error("Erro ao buscar avaliações:");
    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});