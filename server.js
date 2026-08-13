const express = require("express");
const crypto = require("crypto");
require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

const PARTNER_ID = Number(process.env.SHOPEE_PARTNER_ID);
const PARTNER_KEY = process.env.SHOPEE_PARTNER_KEY;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false
    }
  }
);

let authState = {
  shopId: null,
  accessToken: null,
  refreshToken: null,
  expiresAt: null
};

let itemDiagnosticState = {
  itensProcessados: new Set(),
  resultados: [],
  erros: [],
  iniciadoEm: null
};

let scanState = {
  comentarios: new Map(),
  itensProcessados: new Set(),
  erros: [],
  iniciadoEm: null
};

let diagnoseAllState = {
  running: false,
  concluido: false,
  totalItens: 0,
  itensProcessados: 0,
  resultados: [],
  erros: [],
  iniciadoEm: null,
  finalizadoEm: null
};

let fullReviewScanState = {
  running: false,
  concluido: false,

  totalItens: 0,
  itensProcessados: 0,

  itensPorStatus: {
    NORMAL: 0,
    DELETED: 0,
    UNLIST: 0
  },

  itensProcessadosPorStatus: {
    NORMAL: 0,
    DELETED: 0,
    UNLIST: 0
  },

  comentarios: new Map(),

  erros: [],

  iniciadoEm: null,
  finalizadoEm: null
};

let fullDbSyncState = {
  running: false,
  concluido: false,

  totalItens: 0,
  itensProcessados: 0,

  totalAvaliacoesRecebidas: 0,
  totalGravadas: 0,

  totalPendentes: 0,
  totalRespondidas: 0,

  erros: [],

  iniciadoEm: null,
  finalizadoEm: null
};

let replyEngineState = {
  running: false,
  iniciadoEm: null,
  finalizadoEm: null,
  ultimoResultado: null
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

async function contarRespostasHoje(shopId) {
  const {
    data,
    error
  } = await supabase.rpc(
    "contar_respostas_hoje_sp",
    {
      p_shop_id: Number(shopId)
    }
  );

  if (error) {
    throw new Error(
      `Erro ao contar respostas do dia em São Paulo: ${error.message}`
    );
  }

  return Number(data || 0);
}

async function carregarAuthStateDoSupabase() {
  const {
    data,
    error
  } = await supabase
    .from("shopee_shops")
    .select(`
      shop_id,
      access_token,
      refresh_token,
      token_expires_at,
      ativa
    `)
    .eq("shop_name", "Key Quality")
    .eq("ativa", true)
    .maybeSingle();

  if (error) {
    throw new Error(
      `Erro ao carregar autenticação da Shopee: ${error.message}`
    );
  }

  if (!data) {
    console.log(
      "Nenhuma autenticação Shopee persistida encontrada."
    );

    return false;
  }

  authState = {
    shopId:
      Number(data.shop_id),

    accessToken:
      data.access_token,

    refreshToken:
      data.refresh_token,

    expiresAt:
      data.token_expires_at
        ? new Date(
            data.token_expires_at
          ).getTime()
        : 0
  };

  console.log(
    `Autenticação Shopee carregada do Supabase para shop_id ${authState.shopId}`
  );

  return true;
}

async function renovarTokenShopeeSeNecessario(forcar = false) {
  const agora = Date.now();

  // margem de segurança de 5 minutos
  const margem = 5 * 60 * 1000;

  if (
  !forcar &&
  authState.accessToken &&
  authState.expiresAt &&
  authState.expiresAt - agora > margem
) {
    return {
      renovado: false,
      motivo: "Token ainda válido."
    };
  }

  if (!authState.refreshToken || !authState.shopId) {
    throw new Error(
      "Não há refresh_token ou shop_id disponível para renovar o token."
    );
  }

  const path =
  "/api/v2/auth/access_token/get";

  const timestamp =
    Math.floor(Date.now() / 1000);

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
      refresh_token:
        authState.refreshToken,

      partner_id:
        Number(PARTNER_ID),

      shop_id:
        Number(authState.shopId)
    })
  });

  const data =
    await response.json();

  if (data.error) {
    throw new Error(
      `Erro ao renovar token Shopee: ${JSON.stringify(data)}`
    );
  }

  const novoExpiresAt =
    Date.now() +
    Number(data.expire_in) * 1000;

  authState.accessToken =
    data.access_token;

  authState.refreshToken =
    data.refresh_token;

  authState.expiresAt =
    novoExpiresAt;

  const {
    error: erroBanco
  } = await supabase
    .from("shopee_shops")
    .update({
      access_token:
        data.access_token,

      refresh_token:
        data.refresh_token,

      token_expires_at:
        new Date(
          novoExpiresAt
        ).toISOString(),

      updated_at:
        new Date().toISOString()
    })
    .eq(
      "shop_id",
      Number(authState.shopId)
    );

  if (erroBanco) {
    throw new Error(
      `Token renovado na Shopee, mas houve erro ao salvar no Supabase: ${erroBanco.message}`
    );
  }

  return {
    renovado: true,
    shop_id:
      Number(authState.shopId),
    expire_in:
      data.expire_in
  };
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

    const tokenExpiresAt =
  new Date(
    Date.now() + Number(data.expire_in) * 1000
  ).toISOString();

const {
  error: erroSalvarShop
} = await supabase
  .from("shopee_shops")
  .upsert(
    {
      shop_id:
        Number(authState.shopId),

      shop_name:
        "Key Quality",

      access_token:
        authState.accessToken,

      refresh_token:
        authState.refreshToken,

      token_expires_at:
        tokenExpiresAt,

      ativa:
        true,

      updated_at:
        new Date().toISOString()
    },
    {
      onConflict: "shop_id"
    }
  );

if (erroSalvarShop) {
  throw new Error(
    `Erro ao salvar token da loja no Supabase: ${erroSalvarShop.message}`
  );
}

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

app.get("/pending-reviews", async (req, res) => {
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

    let cursor = "";
    let more = true;

    const todasAvaliacoes = [];

    while (more) {
      const timestamp = Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        path,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      let url =
        `https://partner.shopeemobile.com${path}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&page_size=100`;

      if (cursor) {
        url += `&cursor=${encodeURIComponent(cursor)}`;
      }

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        console.error("Erro Shopee:", data);

        return res.status(400).json({
          ok: false,
          shopee_error: data
        });
      }

      const responseData = data.response || {};

      const lista = responseData.item_comment_list || [];

      todasAvaliacoes.push(...lista);

      more = responseData.more === true;
      cursor = responseData.next_cursor || "";

      if (more && !cursor) {
        break;
      }
    }

    const pendentes = todasAvaliacoes.filter(
      avaliacao => !avaliacao.comment_reply
    );

    const resultado = pendentes.map(avaliacao => ({
      comment_id: avaliacao.comment_id,
      buyer_username: avaliacao.buyer_username,
      rating_star: avaliacao.rating_star,
      comment: avaliacao.comment,
      order_sn: avaliacao.order_sn,
      item_id: avaliacao.item_id,
      create_time: avaliacao.create_time
    }));

    console.log(
      `Avaliações encontradas: ${todasAvaliacoes.length}`
    );

    console.log(
      `Avaliações pendentes: ${resultado.length}`
    );

    return res.json({
      ok: true,
      total_avaliacoes: todasAvaliacoes.length,
      total_pendentes: resultado.length,
      pendentes: resultado
    });

  } catch (error) {
    console.error("Erro ao buscar avaliações pendentes:");
    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/items", async (req, res) => {
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

    const path = "/api/v2/product/get_item_list";

    let offset = 0;
    const pageSize = 100;
    let hasNextPage = true;

    const itens = [];

    while (hasNextPage) {
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
        `&offset=${offset}` +
        `&page_size=${pageSize}` +
        `&item_status=NORMAL`;

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        return res.status(400).json({
          ok: false,
          shopee_error: data
        });
      }

      const lista = data.response?.item || [];

      itens.push(...lista);

      hasNextPage =
        data.response?.has_next_page === true;

      offset =
        data.response?.next_offset ?? offset + lista.length;

      if (lista.length === 0) {
        break;
      }
    }

    return res.json({
      ok: true,
      total_itens: itens.length,
      itens: itens.map(item => ({
        item_id: item.item_id,
        item_status: item.item_status,
        update_time: item.update_time
      }))
    });

  } catch (error) {
    console.error("Erro ao buscar itens:");
    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/pending-by-items-test", async (req, res) => {
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

    // ==========================
    // 1. BUSCAR ITENS DA LOJA
    // ==========================

    const itemListPath = "/api/v2/product/get_item_list";

    let offset = 0;
    const itemPageSize = 100;
    let hasNextPage = true;

    const itens = [];

    while (hasNextPage && itens.length < 10) {
      const timestamp = Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        itemListPath,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      const url =
        `https://partner.shopeemobile.com${itemListPath}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&offset=${offset}` +
        `&page_size=${itemPageSize}` +
        `&item_status=NORMAL`;

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        return res.status(400).json({
          ok: false,
          etapa: "get_item_list",
          shopee_error: data
        });
      }

      const lista = data.response?.item || [];

      itens.push(...lista);

      hasNextPage =
        data.response?.has_next_page === true;

      offset =
        data.response?.next_offset ?? offset + lista.length;

      if (lista.length === 0) {
        break;
      }
    }

   const itensTeste = [
  { item_id: 22692791794 }
];

    // ==========================
    // 2. BUSCAR AVALIAÇÕES
    // ITEM POR ITEM
    // ==========================

    const commentPath = "/api/v2/product/get_comment";

    const todasAvaliacoes = [];

    const resumoItens = [];

    for (const item of itensTeste) {
      let cursor = "";
      let more = true;

      let totalItem = 0;

      while (more) {
        const timestamp = Math.floor(Date.now() / 1000);

        const sign = gerarAssinatura(
          commentPath,
          timestamp,
          authState.accessToken,
          authState.shopId
        );

        let url =
          `https://partner.shopeemobile.com${commentPath}` +
          `?partner_id=${PARTNER_ID}` +
          `&timestamp=${timestamp}` +
          `&access_token=${authState.accessToken}` +
          `&shop_id=${authState.shopId}` +
          `&sign=${sign}` +
          `&page_size=100` +
          `&item_id=${item.item_id}`;

        if (cursor) {
          url += `&cursor=${encodeURIComponent(cursor)}`;
        }

        const response = await fetch(url);
        const data = await response.json();

        if (data.error) {
          resumoItens.push({
            item_id: item.item_id,
            erro: data
          });

          break;
        }

        const lista =
          data.response?.item_comment_list || [];

        todasAvaliacoes.push(...lista);

        totalItem += lista.length;

        more =
          data.response?.more === true;

        cursor =
          data.response?.next_cursor || "";

        if (more && !cursor) {
          break;
        }
      }

      resumoItens.push({
        item_id: item.item_id,
        total_avaliacoes: totalItem
      });
    }

    // ==========================
    // 3. REMOVER DUPLICADAS
    // ==========================

    const mapa = new Map();

    for (const avaliacao of todasAvaliacoes) {
      mapa.set(
        String(avaliacao.comment_id),
        avaliacao
      );
    }

    const avaliacoesUnicas =
      Array.from(mapa.values());

    // ==========================
    // 4. FILTRAR PENDENTES
    // ==========================

    const pendentes =
      avaliacoesUnicas.filter(
        avaliacao => !avaliacao.comment_reply
      );

    // ==========================
    // 5. RESUMO
    // ==========================

    const porEstrela = {
      1: 0,
      2: 0,
      3: 0,
      4: 0,
      5: 0
    };

    let semComentario = 0;
    let comComentario = 0;

    for (const avaliacao of pendentes) {
      const estrela =
        Number(avaliacao.rating_star);

      if (porEstrela[estrela] !== undefined) {
        porEstrela[estrela]++;
      }

      if (
        !avaliacao.comment ||
        avaliacao.comment.trim() === ""
      ) {
        semComentario++;
      } else {
        comComentario++;
      }
    }

    return res.json({
      ok: true,

      itens_testados:
        itensTeste.length,

      total_avaliacoes_encontradas:
        todasAvaliacoes.length,

      total_avaliacoes_unicas:
        avaliacoesUnicas.length,

      total_pendentes:
        pendentes.length,

      pendentes_sem_comentario:
        semComentario,

      pendentes_com_comentario:
        comComentario,

      pendentes_por_estrela:
        porEstrela,

      resumo_itens:
        resumoItens,

      amostra_pendentes:
        pendentes
          .slice(0, 20)
          .map(avaliacao => ({
            comment_id:
              avaliacao.comment_id,

            item_id:
              avaliacao.item_id,

            buyer_username:
              avaliacao.buyer_username,

            rating_star:
              avaliacao.rating_star,

            comment:
              avaliacao.comment || ""
          }))

          ,

debug_avaliacoes_encontradas:
  todasAvaliacoes.map(avaliacao => ({
    comment_id: avaliacao.comment_id,
    item_id: avaliacao.item_id,
    buyer_username: avaliacao.buyer_username,
    rating_star: avaliacao.rating_star,
    comment: avaliacao.comment || "",
    tem_resposta: !!avaliacao.comment_reply
  }))

    });

  } catch (error) {
    console.error(
      "Erro no teste item por item:"
    );

    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/scan-pending", async (req, res) => {
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

    // ==========================
    // PARÂMETROS DO LOTE
    // ==========================

    const start = Math.max(
      0,
      Number(req.query.start) || 0
    );

    const limit = Math.min(
      50,
      Math.max(1, Number(req.query.limit) || 50)
    );

    // ==========================
    // 1. BUSCAR TODOS OS ITENS
    // ==========================

    const itemListPath =
      "/api/v2/product/get_item_list";

    let offset = 0;
    const itemPageSize = 100;
    let hasNextPage = true;

    const itens = [];

    while (hasNextPage) {
      const timestamp =
        Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        itemListPath,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      const url =
        `https://partner.shopeemobile.com${itemListPath}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&offset=${offset}` +
        `&page_size=${itemPageSize}` +
        `&item_status=NORMAL`;

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        return res.status(400).json({
          ok: false,
          etapa: "get_item_list",
          shopee_error: data
        });
      }

      const lista =
        data.response?.item || [];

      itens.push(...lista);

      hasNextPage =
        data.response?.has_next_page === true;

      offset =
        data.response?.next_offset ??
        offset + lista.length;

      if (lista.length === 0) {
        break;
      }
    }

    // ==========================
    // 2. DEFINIR O LOTE
    // ==========================

    const lote = itens.slice(
      start,
      start + limit
    );

    if (lote.length === 0) {
      return res.json({
        ok: true,
        concluido: true,
        message:
          "Não existem mais itens nesse intervalo.",
        total_itens_loja: itens.length,
        proximo_start: null
      });
    }

    if (!scanState.iniciadoEm) {
      scanState.iniciadoEm =
        new Date().toISOString();
    }

    const commentPath =
      "/api/v2/product/get_comment";

    let avaliacoesNesteLote = 0;
    let itensComAvaliacao = 0;

    // ==========================
    // 3. PROCESSAR ITEM A ITEM
    // ==========================

    for (const item of lote) {
      const itemId = Number(item.item_id);

      // Não repetir item já processado
      if (
        scanState.itensProcessados.has(
          String(itemId)
        )
      ) {
        continue;
      }

      let cursor = "";
      let more = true;
      let totalItem = 0;

      try {
        while (more) {
          const timestamp =
            Math.floor(Date.now() / 1000);

          const sign = gerarAssinatura(
            commentPath,
            timestamp,
            authState.accessToken,
            authState.shopId
          );

          let url =
            `https://partner.shopeemobile.com${commentPath}` +
            `?partner_id=${PARTNER_ID}` +
            `&timestamp=${timestamp}` +
            `&access_token=${authState.accessToken}` +
            `&shop_id=${authState.shopId}` +
            `&sign=${sign}` +
            `&page_size=100` +
            `&item_id=${itemId}`;

          if (cursor) {
            url +=
              `&cursor=${encodeURIComponent(cursor)}`;
          }

          const response = await fetch(url);
          const data = await response.json();

          if (data.error) {
            throw new Error(
              JSON.stringify(data)
            );
          }

          const lista =
            data.response?.item_comment_list ||
            [];

          for (const avaliacao of lista) {
            scanState.comentarios.set(
              String(avaliacao.comment_id),
              avaliacao
            );
          }

          totalItem += lista.length;

          more =
            data.response?.more === true;

          cursor =
            data.response?.next_cursor || "";

          if (more && !cursor) {
            break;
          }
        }

        if (totalItem > 0) {
          itensComAvaliacao++;
        }

        avaliacoesNesteLote += totalItem;

        scanState.itensProcessados.add(
          String(itemId)
        );

      } catch (error) {
        scanState.erros.push({
          item_id: itemId,
          erro: error.message
        });
      }

      // Pequeno intervalo entre itens
      await new Promise(resolve =>
        setTimeout(resolve, 150)
      );
    }

    // ==========================
    // 4. CONSOLIDAR
    // ==========================

    const todasAvaliacoes =
      Array.from(
        scanState.comentarios.values()
      );

    const pendentes =
      todasAvaliacoes.filter(
        avaliacao =>
          !avaliacao.comment_reply
      );

    let semComentario = 0;
    let comComentario = 0;

    const porEstrela = {
      1: 0,
      2: 0,
      3: 0,
      4: 0,
      5: 0
    };

    for (const avaliacao of pendentes) {
      const estrela =
        Number(avaliacao.rating_star);

      if (
        porEstrela[estrela] !== undefined
      ) {
        porEstrela[estrela]++;
      }

      if (
        !avaliacao.comment ||
        avaliacao.comment.trim() === ""
      ) {
        semComentario++;
      } else {
        comComentario++;
      }
    }

    const proximoStart =
      start + lote.length;

    const concluido =
      proximoStart >= itens.length;

    return res.json({
      ok: true,

      concluido,

      lote: {
        start,
        limit,
        itens_no_lote: lote.length,
        itens_com_avaliacao:
          itensComAvaliacao,
        avaliacoes_encontradas:
          avaliacoesNesteLote
      },

      acumulado: {
        total_itens_loja:
          itens.length,

        itens_processados:
          scanState.itensProcessados.size,

        avaliacoes_unicas:
          todasAvaliacoes.length,

        total_pendentes:
          pendentes.length,

        pendentes_sem_comentario:
          semComentario,

        pendentes_com_comentario:
          comComentario,

        pendentes_por_estrela:
          porEstrela,

        erros:
          scanState.erros.length
      },

      proximo_start:
        concluido
          ? null
          : proximoStart,

      iniciado_em:
        scanState.iniciadoEm
    });

  } catch (error) {
    console.error(
      "Erro no scanner:"
    );

    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/scan-reset", (req, res) => {
  scanState = {
    comentarios: new Map(),
    itensProcessados: new Set(),
    erros: [],
    iniciadoEm: null
  };

  return res.json({
    ok: true,
    message:
      "Scanner zerado com sucesso."
  });
});

app.get("/diagnose-item-limits", async (req, res) => {
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

    const start = Math.max(
      0,
      Number(req.query.start) || 0
    );

    const limit = Math.min(
      50,
      Math.max(1, Number(req.query.limit) || 50)
    );

    // ====================================
    // 1. BUSCAR TODOS OS ITENS
    // ====================================

    const itemListPath =
      "/api/v2/product/get_item_list";

    let offset = 0;
    const itemPageSize = 100;
    let hasNextPage = true;

    const itens = [];

    while (hasNextPage) {
      const timestamp =
        Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        itemListPath,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      const url =
        `https://partner.shopeemobile.com${itemListPath}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&offset=${offset}` +
        `&page_size=${itemPageSize}` +
        `&item_status=NORMAL`;

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        return res.status(400).json({
          ok: false,
          etapa: "get_item_list",
          shopee_error: data
        });
      }

      const lista =
        data.response?.item || [];

      itens.push(...lista);

      hasNextPage =
        data.response?.has_next_page === true;

      offset =
        data.response?.next_offset ??
        offset + lista.length;

      if (lista.length === 0) {
        break;
      }
    }

    // ====================================
    // 2. PROCESSAR O LOTE
    // ====================================

    const lote = itens.slice(
      start,
      start + limit
    );

    if (!itemDiagnosticState.iniciadoEm) {
      itemDiagnosticState.iniciadoEm =
        new Date().toISOString();
    }

    const commentPath =
      "/api/v2/product/get_comment";

    for (const item of lote) {
      const itemId = Number(item.item_id);

      if (
        itemDiagnosticState.itensProcessados.has(
          String(itemId)
        )
      ) {
        continue;
      }

      let cursor = "";
      let more = true;
      let totalItem = 0;

      try {
        while (more) {
          const timestamp =
            Math.floor(Date.now() / 1000);

          const sign = gerarAssinatura(
            commentPath,
            timestamp,
            authState.accessToken,
            authState.shopId
          );

          let url =
            `https://partner.shopeemobile.com${commentPath}` +
            `?partner_id=${PARTNER_ID}` +
            `&timestamp=${timestamp}` +
            `&access_token=${authState.accessToken}` +
            `&shop_id=${authState.shopId}` +
            `&sign=${sign}` +
            `&page_size=100` +
            `&item_id=${itemId}`;

          if (cursor) {
            url +=
              `&cursor=${encodeURIComponent(cursor)}`;
          }

          const response = await fetch(url);
          const data = await response.json();

          if (data.error) {
            throw new Error(
              JSON.stringify(data)
            );
          }

          const lista =
            data.response?.item_comment_list || [];

          totalItem += lista.length;

          more =
            data.response?.more === true;

          cursor =
            data.response?.next_cursor || "";

          if (more && !cursor) {
            break;
          }

          // Segurança: teto oficial
          if (totalItem >= 1000) {
            break;
          }
        }

        itemDiagnosticState.resultados.push({
          item_id: itemId,
          total_avaliacoes: totalItem,
          atingiu_limite:
            totalItem >= 1000
        });

        itemDiagnosticState.itensProcessados.add(
          String(itemId)
        );

      } catch (error) {
        itemDiagnosticState.erros.push({
          item_id: itemId,
          erro: error.message
        });
      }

      await new Promise(resolve =>
        setTimeout(resolve, 150)
      );
    }

    // ====================================
    // 3. RESUMO
    // ====================================

    const ordenados =
      [...itemDiagnosticState.resultados]
        .sort(
          (a, b) =>
            b.total_avaliacoes -
            a.total_avaliacoes
        );

    const itensNoLimite =
      ordenados.filter(
        item => item.atingiu_limite
      );

    const acima500 =
      ordenados.filter(
        item =>
          item.total_avaliacoes >= 500
      );

    const proximoStart =
      start + lote.length;

    const concluido =
      proximoStart >= itens.length;

    return res.json({
      ok: true,

      concluido,

      total_itens_loja:
        itens.length,

      itens_processados:
        itemDiagnosticState
          .itensProcessados.size,

      itens_com_1000:
        itensNoLimite.length,

      itens_com_500_ou_mais:
        acima500.length,

      top_20_itens:
        ordenados.slice(0, 20),

      itens_no_limite:
        itensNoLimite,

      erros:
        itemDiagnosticState.erros.length,

      proximo_start:
        concluido
          ? null
          : proximoStart,

      iniciado_em:
        itemDiagnosticState.iniciadoEm
    });

  } catch (error) {
    console.error(
      "Erro no diagnóstico de itens:"
    );

    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/diagnose-reset", (req, res) => {
  itemDiagnosticState = {
    itensProcessados: new Set(),
    resultados: [],
    erros: [],
    iniciadoEm: null
  };

  return res.json({
    ok: true,
    message:
      "Diagnóstico zerado com sucesso."
  });
});

async function executarDiagnosticoCompleto() {
  try {
    diagnoseAllState.running = true;
    diagnoseAllState.concluido = false;
    diagnoseAllState.totalItens = 0;
    diagnoseAllState.itensProcessados = 0;
    diagnoseAllState.resultados = [];
    diagnoseAllState.erros = [];
    diagnoseAllState.iniciadoEm = new Date().toISOString();
    diagnoseAllState.finalizadoEm = null;

    console.log("Iniciando diagnóstico completo...");

    // ===================================
    // 1. BUSCAR TODOS OS ITENS
    // ===================================

    const itemListPath =
      "/api/v2/product/get_item_list";

    let offset = 0;
    const pageSize = 100;
    let hasNextPage = true;

    const itens = [];

    while (hasNextPage) {
      const timestamp =
        Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        itemListPath,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      const url =
        `https://partner.shopeemobile.com${itemListPath}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&offset=${offset}` +
        `&page_size=${pageSize}` +
        `&item_status=NORMAL`;

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        throw new Error(
          `Erro get_item_list: ${JSON.stringify(data)}`
        );
      }

      const lista =
        data.response?.item || [];

      itens.push(...lista);

      hasNextPage =
        data.response?.has_next_page === true;

      offset =
        data.response?.next_offset ??
        offset + lista.length;

      if (lista.length === 0) {
        break;
      }
    }

    diagnoseAllState.totalItens =
      itens.length;

    console.log(
      `Itens encontrados: ${itens.length}`
    );

    // ===================================
    // 2. BUSCAR AVALIAÇÕES ITEM POR ITEM
    // ===================================

    const commentPath =
      "/api/v2/product/get_comment";

    for (const item of itens) {
      const itemId =
        Number(item.item_id);

      let cursor = "";
      let more = true;
      let totalItem = 0;

      try {
        while (more) {
          const timestamp =
            Math.floor(Date.now() / 1000);

          const sign = gerarAssinatura(
            commentPath,
            timestamp,
            authState.accessToken,
            authState.shopId
          );

          let url =
            `https://partner.shopeemobile.com${commentPath}` +
            `?partner_id=${PARTNER_ID}` +
            `&timestamp=${timestamp}` +
            `&access_token=${authState.accessToken}` +
            `&shop_id=${authState.shopId}` +
            `&sign=${sign}` +
            `&page_size=100` +
            `&item_id=${itemId}`;

          if (cursor) {
            url +=
              `&cursor=${encodeURIComponent(cursor)}`;
          }

          const response =
            await fetch(url);

          const data =
            await response.json();

          if (data.error) {
            throw new Error(
              JSON.stringify(data)
            );
          }

          const lista =
            data.response
              ?.item_comment_list || [];

          totalItem +=
            lista.length;

          more =
            data.response?.more === true;

          cursor =
            data.response?.next_cursor || "";

          if (more && !cursor) {
            break;
          }

          if (totalItem >= 1000) {
            break;
          }
        }

        diagnoseAllState.resultados.push({
          item_id: itemId,
          total_avaliacoes: totalItem,
          atingiu_limite:
            totalItem >= 1000
        });

      } catch (error) {
        diagnoseAllState.erros.push({
          item_id: itemId,
          erro: error.message
        });
      }

      diagnoseAllState.itensProcessados++;

      // Log a cada 50 itens
      if (
        diagnoseAllState.itensProcessados %
          50 ===
        0
      ) {
        console.log(
          `Diagnóstico: ${diagnoseAllState.itensProcessados}/${diagnoseAllState.totalItens}`
        );
      }

      // pequena pausa para não bombardear a API
      await new Promise(resolve =>
        setTimeout(resolve, 150)
      );
    }

    diagnoseAllState.running = false;
    diagnoseAllState.concluido = true;
    diagnoseAllState.finalizadoEm =
      new Date().toISOString();

    console.log(
      "Diagnóstico completo finalizado."
    );

  } catch (error) {
    console.error(
      "Erro no diagnóstico completo:"
    );

    console.error(error);

    diagnoseAllState.running = false;
    diagnoseAllState.concluido = false;

    diagnoseAllState.erros.push({
      geral: true,
      erro: error.message
    });
  }
}

app.get("/diagnose-all", async (req, res) => {
  if (
    !authState.accessToken ||
    !authState.shopId
  ) {
    return res.status(401).json({
      ok: false,
      message:
        "Loja ainda não autorizada nesta execução."
    });
  }

  if (
    authState.expiresAt <= Date.now()
  ) {
    return res.status(401).json({
      ok: false,
      message:
        "Access token expirado."
    });
  }

  if (diagnoseAllState.running) {
    return res.json({
      ok: true,
      message:
        "Diagnóstico já está em execução.",
      itens_processados:
        diagnoseAllState.itensProcessados,
      total_itens:
        diagnoseAllState.totalItens
    });
  }

  executarDiagnosticoCompleto();

  return res.json({
    ok: true,
    message:
      "Diagnóstico completo iniciado.",
    status_url:
      "/diagnose-status"
  });
});

app.get("/diagnose-status", (req, res) => {
  const ordenados =
    [...diagnoseAllState.resultados]
      .sort(
        (a, b) =>
          b.total_avaliacoes -
          a.total_avaliacoes
      );

  const itensCom1000 =
    ordenados.filter(
      item =>
        item.total_avaliacoes >= 1000
    );

  const itensCom500 =
    ordenados.filter(
      item =>
        item.total_avaliacoes >= 500
    );

  let progresso = 0;

  if (
    diagnoseAllState.totalItens > 0
  ) {
    progresso =
      (
        diagnoseAllState
          .itensProcessados /
        diagnoseAllState.totalItens *
        100
      ).toFixed(1);
  }

  return res.json({
    ok: true,

    running:
      diagnoseAllState.running,

    concluido:
      diagnoseAllState.concluido,

    progresso_percentual:
      Number(progresso),

    total_itens:
      diagnoseAllState.totalItens,

    itens_processados:
      diagnoseAllState.itensProcessados,

    itens_com_1000:
      itensCom1000.length,

    itens_com_500_ou_mais:
      itensCom500.length,

    top_20_itens:
      ordenados.slice(0, 20),

    itens_no_limite:
      itensCom1000,

    erros:
      diagnoseAllState.erros.length,

    detalhes_erros:
      diagnoseAllState.erros.slice(0, 20),

    iniciado_em:
      diagnoseAllState.iniciadoEm,

    finalizado_em:
      diagnoseAllState.finalizadoEm
  });
});

app.get("/item-status-diagnostic", async (req, res) => {
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

    const path = "/api/v2/product/get_item_list";

    const statusParaTestar = [
      "NORMAL",
      "BANNED",
      "DELETED",
      "UNLIST"
    ];

    const resultados = [];

    for (const status of statusParaTestar) {
      let offset = 0;
      const pageSize = 100;
      let hasNextPage = true;

      const itens = [];

      try {
        while (hasNextPage) {
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
            `&offset=${offset}` +
            `&page_size=${pageSize}` +
            `&item_status=${status}`;

          const response = await fetch(url);
          const data = await response.json();

          if (data.error) {
            resultados.push({
              status,
              suportado: false,
              erro: data
            });

            break;
          }

          const lista = data.response?.item || [];

          itens.push(...lista);

          hasNextPage =
            data.response?.has_next_page === true;

          offset =
            data.response?.next_offset ??
            offset + lista.length;

          if (lista.length === 0) {
            break;
          }
        }

        if (
          !resultados.some(
            resultado =>
              resultado.status === status &&
              resultado.suportado === false
          )
        ) {
          resultados.push({
            status,
            suportado: true,
            total_itens: itens.length,
            amostra_item_ids: itens
              .slice(0, 10)
              .map(item => item.item_id)
          });
        }

      } catch (error) {
        resultados.push({
          status,
          suportado: false,
          erro: error.message
        });
      }
    }

    const totalEncontrado = resultados
      .filter(resultado => resultado.suportado)
      .reduce(
        (total, resultado) =>
          total + (resultado.total_itens || 0),
        0
      );

    return res.json({
      ok: true,
      total_itens_encontrados:
        totalEncontrado,
      resultados
    });

  } catch (error) {
    console.error(
      "Erro no diagnóstico de status:"
    );

    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

async function executarScanCompletoAvaliacoes() {
  try {

fullDbSyncState = {
  running: true,
  concluido: false,

  totalItens: 0,
  itensProcessados: 0,

  totalAvaliacoesRecebidas: 0,
  totalGravadas: 0,

  totalPendentes: 0,
  totalRespondidas: 0,

  erros: [],

  iniciadoEm: new Date().toISOString(),
  finalizadoEm: null
};

    fullReviewScanState = {
      running: true,
      concluido: false,

      totalItens: 0,
      itensProcessados: 0,

      itensPorStatus: {
        NORMAL: 0,
        DELETED: 0,
        UNLIST: 0
      },

      itensProcessadosPorStatus: {
        NORMAL: 0,
        DELETED: 0,
        UNLIST: 0
      },

      comentarios: new Map(),

      erros: [],

      iniciadoEm: new Date().toISOString(),
      finalizadoEm: null
    };

    console.log(
      "Iniciando scanner completo de avaliações..."
    );

    // =====================================
    // 1. BUSCAR ITENS DE TODOS OS STATUS
    // =====================================

    const itemListPath =
      "/api/v2/product/get_item_list";

    const statusLista = [
      "NORMAL",
      "DELETED",
      "UNLIST"
    ];

    const todosItens = [];

    for (const status of statusLista) {
      let offset = 0;
      const pageSize = 100;
      let hasNextPage = true;

      while (hasNextPage) {
        const timestamp =
          Math.floor(Date.now() / 1000);

        const sign = gerarAssinatura(
          itemListPath,
          timestamp,
          authState.accessToken,
          authState.shopId
        );

        const url =
          `https://partner.shopeemobile.com${itemListPath}` +
          `?partner_id=${PARTNER_ID}` +
          `&timestamp=${timestamp}` +
          `&access_token=${authState.accessToken}` +
          `&shop_id=${authState.shopId}` +
          `&sign=${sign}` +
          `&offset=${offset}` +
          `&page_size=${pageSize}` +
          `&item_status=${status}`;

        const response = await fetch(url);
        const data = await response.json();

        if (data.error) {
          throw new Error(
            `Erro get_item_list ${status}: ${JSON.stringify(data)}`
          );
        }

        const lista =
          data.response?.item || [];

        for (const item of lista) {
          todosItens.push({
            item_id: Number(item.item_id),
            status
          });
        }

        fullReviewScanState
          .itensPorStatus[status] +=
          lista.length;

        hasNextPage =
          data.response?.has_next_page === true;

        offset =
          data.response?.next_offset ??
          offset + lista.length;

        if (lista.length === 0) {
          break;
        }
      }
    }

    // =====================================
    // 2. REMOVER ITEM_ID DUPLICADO
    // =====================================

    const mapaItens = new Map();

    for (const item of todosItens) {
      mapaItens.set(
        String(item.item_id),
        item
      );
    }

    const itensUnicos =
      Array.from(mapaItens.values());

    fullReviewScanState.totalItens =
      itensUnicos.length;

      fullDbSyncState.totalItens =
  itensUnicos.length;

  const syncJob =
  await obterOuCriarSyncJob(
    Number(authState.shopId)
  );

const indiceInicial =
  Number(
    syncJob.ultimo_indice_processado ?? -1
  ) + 1;

fullDbSyncState.itensProcessados =
  Math.max(
    0,
    indiceInicial
  );

  fullDbSyncState.totalAvaliacoesRecebidas =
  Number(syncJob.total_avaliacoes || 0);

fullDbSyncState.totalGravadas =
  Number(syncJob.total_gravadas || 0);

fullDbSyncState.totalPendentes =
  Number(syncJob.total_pendentes || 0);

fullDbSyncState.totalRespondidas =
  Number(syncJob.total_respondidas || 0);

const { error: erroInicioJob } =
  await supabase
    .from("sync_jobs")
    .update({
      status: "EXECUTANDO",
      total_itens: itensUnicos.length,
      iniciado_em:
        syncJob.iniciado_em ||
        new Date().toISOString(),
      updated_at: new Date().toISOString()
    })
    .eq("id", syncJob.id);

if (erroInicioJob) {
  throw new Error(
    `Erro ao iniciar checkpoint: ${erroInicioJob.message}`
  );
}

console.log(
  `Retomando sincronização a partir do índice ${indiceInicial}`
);

    console.log(
      `Itens únicos para processar: ${itensUnicos.length}`
    );

    console.log(
      "Itens por status:",
      fullReviewScanState.itensPorStatus
    );

    // =====================================
    // 3. BUSCAR AVALIAÇÕES ITEM POR ITEM
    // =====================================

    const commentPath =
      "/api/v2/product/get_comment";

    for (
  let indice = indiceInicial;
  indice < itensUnicos.length;
  indice++
) {
  const item = itensUnicos[indice];
      const itemId =
        Number(item.item_id);

      const status =
        item.status;

      let cursor = "";
      let more = true;
      let totalItem = 0;

      try {
        while (more) {
          const timestamp =
            Math.floor(Date.now() / 1000);

          const sign = gerarAssinatura(
            commentPath,
            timestamp,
            authState.accessToken,
            authState.shopId
          );

          let url =
            `https://partner.shopeemobile.com${commentPath}` +
            `?partner_id=${PARTNER_ID}` +
            `&timestamp=${timestamp}` +
            `&access_token=${authState.accessToken}` +
            `&shop_id=${authState.shopId}` +
            `&sign=${sign}` +
            `&page_size=100` +
            `&item_id=${itemId}`;

          if (cursor) {
            url +=
              `&cursor=${encodeURIComponent(cursor)}`;
          }

          const response =
            await fetch(url);

          const data =
            await response.json();

          if (data.error) {
            throw new Error(
              JSON.stringify(data)
            );
          }

          const lista =
            data.response
              ?.item_comment_list || [];

              const resultadoBanco =
  await salvarAvaliacoesNoSupabase(
    lista,
    status
  );

fullDbSyncState.totalAvaliacoesRecebidas +=
  lista.length;

fullDbSyncState.totalGravadas +=
  resultadoBanco.gravadas;

fullDbSyncState.totalPendentes +=
  resultadoBanco.pendentes;

fullDbSyncState.totalRespondidas +=
  resultadoBanco.respondidas;

          for (const avaliacao of lista) {
            fullReviewScanState
              .comentarios
              .set(
                String(
                  avaliacao.comment_id
                ),
                {
                  ...avaliacao,
                  item_status: status
                }
              );
          }

          totalItem +=
            lista.length;

          more =
            data.response?.more === true;

          cursor =
            data.response?.next_cursor || "";

          if (more && !cursor) {
            break;
          }

          // teto conhecido do endpoint
          if (totalItem >= 1000) {
            break;
          }
        }

      } catch (error) {
        fullReviewScanState.erros.push({
          item_id: itemId,
          status,
          erro: error.message
        });
      }

      fullReviewScanState
        .itensProcessados++;

        fullDbSyncState
  .itensProcessados++;

  const {
  error: erroCheckpoint
} = await supabase
  .from("sync_jobs")
  .update({
    status: "EXECUTANDO",

    total_itens:
      itensUnicos.length,

    itens_processados:
      indice + 1,

    ultimo_indice_processado:
      indice,

    total_avaliacoes:
      fullDbSyncState
        .totalAvaliacoesRecebidas,

    total_gravadas:
      fullDbSyncState
        .totalGravadas,

    total_pendentes:
      fullDbSyncState
        .totalPendentes,

    total_respondidas:
      fullDbSyncState
        .totalRespondidas,

    total_erros:
      fullDbSyncState
        .erros.length,

    updated_at:
      new Date().toISOString()
  })
  .eq("id", syncJob.id);

if (erroCheckpoint) {
  throw new Error(
    `Erro ao salvar checkpoint: ${erroCheckpoint.message}`
  );
}

      if (
        fullReviewScanState
          .itensProcessadosPorStatus[status]
        !== undefined
      ) {
        fullReviewScanState
          .itensProcessadosPorStatus[status]++;
      }

      if (
        fullReviewScanState
          .itensProcessados %
          50 ===
        0
      ) {
        console.log(
          `Scanner: ${fullReviewScanState.itensProcessados}/${fullReviewScanState.totalItens}`
        );
      }

      // pequena pausa entre anúncios
      await new Promise(resolve =>
        setTimeout(resolve, 150)
      );
    }

    fullReviewScanState.running =
      false;

    fullReviewScanState.concluido =
      true;

    fullReviewScanState.finalizadoEm =
      new Date().toISOString();

      fullDbSyncState.running = false;
fullDbSyncState.concluido = true;
fullDbSyncState.finalizadoEm =
  new Date().toISOString();

  const {
  error: erroConclusaoJob
} = await supabase
  .from("sync_jobs")
  .update({
    status: "CONCLUIDO",

    total_itens:
      itensUnicos.length,

    itens_processados:
      itensUnicos.length,

    ultimo_indice_processado:
      itensUnicos.length - 1,

    total_avaliacoes:
      fullDbSyncState
        .totalAvaliacoesRecebidas,

    total_gravadas:
      fullDbSyncState
        .totalGravadas,

    total_pendentes:
      fullDbSyncState
        .totalPendentes,

    total_respondidas:
      fullDbSyncState
        .totalRespondidas,

    total_erros:
      fullDbSyncState
        .erros.length,

    finalizado_em:
      new Date().toISOString(),

    updated_at:
      new Date().toISOString()
  })
  .eq("id", syncJob.id);

if (erroConclusaoJob) {
  throw new Error(
    `Erro ao concluir checkpoint: ${erroConclusaoJob.message}`
  );
}

    console.log(
      "Scanner completo finalizado."
    );

  } catch (error) {
    console.error(
      "Erro geral no scanner completo:"
    );

    console.error(error);

    fullReviewScanState.running =
      false;

    fullReviewScanState.concluido =
      false;

      fullDbSyncState.running = false;

fullDbSyncState.erros.push({
  geral: true,
  erro: error.message
});

    fullReviewScanState.erros.push({
      geral: true,
      erro: error.message
    });

    try {
  if (typeof syncJob !== "undefined" && syncJob?.id) {
    await supabase
      .from("sync_jobs")
      .update({
        status: "ERRO",
        ultimo_erro: error.message,
        total_erros:
          fullDbSyncState.erros.length,
        updated_at:
          new Date().toISOString()
      })
      .eq("id", syncJob.id);
  }
} catch (erroCheckpointFinal) {
  console.error(
    "Erro ao registrar falha no checkpoint:",
    erroCheckpointFinal
  );
}
  }
}

app.get("/scan-all-reviews", (req, res) => {
  if (
    !authState.accessToken ||
    !authState.shopId
  ) {
    return res.status(401).json({
      ok: false,
      message:
        "Loja ainda não autorizada nesta execução."
    });
  }

  if (
    authState.expiresAt <= Date.now()
  ) {
    return res.status(401).json({
      ok: false,
      message:
        "Access token expirado."
    });
  }

  if (fullReviewScanState.running) {
    return res.json({
      ok: true,
      message:
        "Scanner já está em execução.",
      itens_processados:
        fullReviewScanState.itensProcessados,
      total_itens:
        fullReviewScanState.totalItens
    });
  }

  executarScanCompletoAvaliacoes();

  return res.json({
    ok: true,
    message:
      "Scanner completo iniciado.",
    status_url:
      "/scan-all-status"
  });
});

app.get("/scan-all-status", (req, res) => {
  const avaliacoes =
    Array.from(
      fullReviewScanState
        .comentarios
        .values()
    );

  const pendentes =
    avaliacoes.filter(
      avaliacao =>
        !avaliacao.comment_reply
    );

  const porEstrela = {
    1: 0,
    2: 0,
    3: 0,
    4: 0,
    5: 0
  };

  const pendentesPorStatus = {
    NORMAL: 0,
    DELETED: 0,
    UNLIST: 0
  };

  let semComentario = 0;
  let comComentario = 0;

  for (const avaliacao of pendentes) {
    const estrela =
      Number(avaliacao.rating_star);

    if (
      porEstrela[estrela] !== undefined
    ) {
      porEstrela[estrela]++;
    }

    const status =
      avaliacao.item_status;

    if (
      pendentesPorStatus[status]
      !== undefined
    ) {
      pendentesPorStatus[status]++;
    }

    if (
      !avaliacao.comment ||
      avaliacao.comment.trim() === ""
    ) {
      semComentario++;
    } else {
      comComentario++;
    }
  }

  let progresso = 0;

  if (
    fullReviewScanState.totalItens > 0
  ) {
    progresso =
      (
        fullReviewScanState
          .itensProcessados /
        fullReviewScanState.totalItens *
        100
      ).toFixed(1);
  }

  return res.json({
    ok: true,

    running:
      fullReviewScanState.running,

    concluido:
      fullReviewScanState.concluido,

    progresso_percentual:
      Number(progresso),

    total_itens:
      fullReviewScanState.totalItens,

    itens_processados:
      fullReviewScanState
        .itensProcessados,

    itens_por_status:
      fullReviewScanState
        .itensPorStatus,

    itens_processados_por_status:
      fullReviewScanState
        .itensProcessadosPorStatus,

    avaliacoes_unicas:
      avaliacoes.length,

    total_pendentes:
      pendentes.length,

    pendentes_sem_comentario:
      semComentario,

    pendentes_com_comentario:
      comComentario,

    pendentes_por_estrela:
      porEstrela,

    pendentes_por_status:
      pendentesPorStatus,

    erros:
      fullReviewScanState
        .erros.length,

    detalhes_erros:
      fullReviewScanState
        .erros
        .slice(0, 20),

    iniciado_em:
      fullReviewScanState
        .iniciadoEm,

    finalizado_em:
      fullReviewScanState
        .finalizadoEm
  });
});

app.get("/scan-all-status", (req, res) => {
  const avaliacoes =
    Array.from(
      fullReviewScanState
        .comentarios
        .values()
    );

  const pendentes =
    avaliacoes.filter(
      avaliacao =>
        !avaliacao.comment_reply
    );

  const porEstrela = {
    1: 0,
    2: 0,
    3: 0,
    4: 0,
    5: 0
  };

  const pendentesPorStatus = {
    NORMAL: 0,
    DELETED: 0,
    UNLIST: 0
  };

  let semComentario = 0;
  let comComentario = 0;

  for (const avaliacao of pendentes) {
    const estrela =
      Number(avaliacao.rating_star);

    if (
      porEstrela[estrela] !== undefined
    ) {
      porEstrela[estrela]++;
    }

    const status =
      avaliacao.item_status;

    if (
      pendentesPorStatus[status]
      !== undefined
    ) {
      pendentesPorStatus[status]++;
    }

    if (
      !avaliacao.comment ||
      avaliacao.comment.trim() === ""
    ) {
      semComentario++;
    } else {
      comComentario++;
    }
  }

  let progresso = 0;

  if (
    fullReviewScanState.totalItens > 0
  ) {
    progresso =
      (
        fullReviewScanState
          .itensProcessados /
        fullReviewScanState.totalItens *
        100
      ).toFixed(1);
  }

  return res.json({
    ok: true,

    running:
      fullReviewScanState.running,

    concluido:
      fullReviewScanState.concluido,

    progresso_percentual:
      Number(progresso),

    total_itens:
      fullReviewScanState.totalItens,

    itens_processados:
      fullReviewScanState
        .itensProcessados,

    itens_por_status:
      fullReviewScanState
        .itensPorStatus,

    itens_processados_por_status:
      fullReviewScanState
        .itensProcessadosPorStatus,

    avaliacoes_unicas:
      avaliacoes.length,

    total_pendentes:
      pendentes.length,

    pendentes_sem_comentario:
      semComentario,

    pendentes_com_comentario:
      comComentario,

    pendentes_por_estrela:
      porEstrela,

    pendentes_por_status:
      pendentesPorStatus,

    erros:
      fullReviewScanState
        .erros.length,

    detalhes_erros:
      fullReviewScanState
        .erros
        .slice(0, 20),

    iniciado_em:
      fullReviewScanState
        .iniciadoEm,

    finalizado_em:
      fullReviewScanState
        .finalizadoEm
  });
});

app.get("/diagnose-1000-item", async (req, res) => {
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

    const itemId = 18796892743;

    const path =
      "/api/v2/product/get_comment";

    let cursor = "";
    let more = true;

    let pagina = 0;
    let total = 0;

    const paginas = [];

    // Segurança para impedir loop infinito
    const MAX_PAGINAS = 30;

    while (more && pagina < MAX_PAGINAS) {
      pagina++;

      const timestamp =
        Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        path,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      let url =
        `https://partner.shopeemobile.com${path}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&page_size=100` +
        `&item_id=${itemId}`;

      if (cursor) {
        url +=
          `&cursor=${encodeURIComponent(cursor)}`;
      }

      const response =
        await fetch(url);

      const data =
        await response.json();

      if (data.error) {
        return res.status(400).json({
          ok: false,
          pagina,
          total_antes_do_erro: total,
          shopee_error: data
        });
      }

      const lista =
        data.response
          ?.item_comment_list || [];

      total += lista.length;

      const novoMore =
        data.response?.more === true;

      const novoCursor =
        data.response?.next_cursor || "";

      paginas.push({
        pagina,
        quantidade:
          lista.length,

        total_acumulado:
          total,

        more:
          novoMore,

        cursor_recebido:
          novoCursor || null,

        primeiro_comment_id:
          lista.length > 0
            ? lista[0].comment_id
            : null,

        ultimo_comment_id:
          lista.length > 0
            ? lista[lista.length - 1]
                .comment_id
            : null
      });

      more = novoMore;

      // Proteção contra cursor repetido
      if (
        more &&
        novoCursor === cursor
      ) {
        paginas.push({
          alerta:
            "Shopee repetiu o mesmo cursor."
        });

        break;
      }

      cursor =
        novoCursor;

      if (more && !cursor) {
        paginas.push({
          alerta:
            "Shopee informou more=true, mas não forneceu next_cursor."
        });

        break;
      }

      await new Promise(resolve =>
        setTimeout(resolve, 150)
      );
    }

    return res.json({
      ok: true,

      item_id:
        itemId,

      paginas_consultadas:
        pagina,

      total_avaliacoes:
        total,

      terminou_naturalmente:
        more === false,

      ainda_existe_more:
        more,

      cursor_final:
        cursor || null,

      atingiu_1000:
        total >= 1000,

      atingiu_max_paginas:
        pagina >= MAX_PAGINAS,

      paginas
    });

  } catch (error) {
    console.error(
      "Erro diagnose-1000-item:",
      error
    );

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/diagnose-1000-pending", async (req, res) => {
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

    const itemId = 18796892743;
    const path = "/api/v2/product/get_comment";

    let cursor = "";
    let more = true;

    const avaliacoes = new Map();

    while (more) {
      const timestamp =
        Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        path,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      let url =
        `https://partner.shopeemobile.com${path}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&page_size=100` +
        `&item_id=${itemId}`;

      if (cursor) {
        url +=
          `&cursor=${encodeURIComponent(cursor)}`;
      }

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        return res.status(400).json({
          ok: false,
          shopee_error: data
        });
      }

      const lista =
        data.response?.item_comment_list || [];

      for (const avaliacao of lista) {
        avaliacoes.set(
          String(avaliacao.comment_id),
          avaliacao
        );
      }

      more =
        data.response?.more === true;

      const novoCursor =
        data.response?.next_cursor || "";

      if (more && !novoCursor) {
        break;
      }

      if (novoCursor === cursor && more) {
        break;
      }

      cursor = novoCursor;
    }

    // =====================================
    // CONSOLIDAÇÃO
    // =====================================

    const todas =
      Array.from(avaliacoes.values());

    const pendentes =
      todas.filter(
        avaliacao => !avaliacao.comment_reply
      );

    const respondidas =
      todas.filter(
        avaliacao => !!avaliacao.comment_reply
      );

    const porEstrela = {
      1: 0,
      2: 0,
      3: 0,
      4: 0,
      5: 0
    };

    let pendentesSemComentario = 0;
    let pendentesComComentario = 0;

    for (const avaliacao of pendentes) {
      const estrela =
        Number(avaliacao.rating_star);

      if (porEstrela[estrela] !== undefined) {
        porEstrela[estrela]++;
      }

      if (
        !avaliacao.comment ||
        avaliacao.comment.trim() === ""
      ) {
        pendentesSemComentario++;
      } else {
        pendentesComComentario++;
      }
    }

    // =====================================
    // DATAS
    // =====================================

    const ordenadas =
      [...todas].sort(
        (a, b) =>
          Number(a.create_time) -
          Number(b.create_time)
      );

    const maisAntiga =
      ordenadas.length > 0
        ? ordenadas[0]
        : null;

    const maisNova =
      ordenadas.length > 0
        ? ordenadas[ordenadas.length - 1]
        : null;

    function formatarAvaliacao(avaliacao) {
      if (!avaliacao) {
        return null;
      }

      return {
        comment_id:
          avaliacao.comment_id,

        create_time:
          avaliacao.create_time,

        data_iso:
          new Date(
            Number(avaliacao.create_time) * 1000
          ).toISOString(),

        rating_star:
          avaliacao.rating_star,

        tem_comentario:
          !!(
            avaliacao.comment &&
            avaliacao.comment.trim()
          ),

        respondida:
          !!avaliacao.comment_reply
      };
    }

    return res.json({
      ok: true,

      item_id: itemId,

      total_acessivel:
        todas.length,

      total_pendentes:
        pendentes.length,

      total_respondidas:
        respondidas.length,

      pendentes_sem_comentario:
        pendentesSemComentario,

      pendentes_com_comentario:
        pendentesComComentario,

      pendentes_por_estrela:
        porEstrela,

      avaliacao_mais_antiga_acessivel:
        formatarAvaliacao(maisAntiga),

      avaliacao_mais_nova_acessivel:
        formatarAvaliacao(maisNova)
    });

  } catch (error) {
    console.error(
      "Erro diagnose-1000-pending:",
      error
    );

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/test-reply-candidate", async (req, res) => {
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
      `&page_size=100`;

    const response = await fetch(url);
    const data = await response.json();

    if (data.error) {
      return res.status(400).json({
        ok: false,
        shopee_error: data
      });
    }

    const lista =
      data.response?.item_comment_list || [];

    const candidata = lista.find(avaliacao => {
      const semResposta =
        !avaliacao.comment_reply;

      const cincoEstrelas =
        Number(avaliacao.rating_star) === 5;

      const semComentario =
        !avaliacao.comment ||
        avaliacao.comment.trim() === "";

      return (
        semResposta &&
        cincoEstrelas &&
        semComentario
      );
    });

    if (!candidata) {
      return res.json({
        ok: true,
        encontrada: false,
        message:
          "Nenhuma avaliação 5 estrelas, sem comentário e sem resposta encontrada nesta página."
      });
    }

    return res.json({
      ok: true,

      encontrada: true,

      ATENCAO:
        "Esta rota NÃO respondeu a avaliação.",

      candidata: {
        comment_id:
          candidata.comment_id,

        item_id:
          candidata.item_id,

        buyer_username:
          candidata.buyer_username,

        rating_star:
          candidata.rating_star,

        comment:
          candidata.comment || "",

        editable:
          candidata.editable,

        create_time:
          candidata.create_time,

        data_iso:
          new Date(
            Number(candidata.create_time) * 1000
          ).toISOString()
      }
    });

  } catch (error) {
    console.error(
      "Erro test-reply-candidate:",
      error
    );

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/test-reply-one", async (req, res) => {
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

    // =====================================
    // TRAVA DO TESTE
    // =====================================

    const COMMENT_ID_TESTE = 70371399878449;

    const RESPOSTA_TESTE =
      "Agradecemos muito pela sua avaliação! Ficamos felizes com sua compra e seguimos à disposição sempre que precisar.";

    // =====================================
    // 1. CONFIRMAR QUE A AVALIAÇÃO
    // AINDA ESTÁ SEM RESPOSTA
    // =====================================

    const getPath = "/api/v2/product/get_comment";
    const getTimestamp = Math.floor(Date.now() / 1000);

    const getSign = gerarAssinatura(
      getPath,
      getTimestamp,
      authState.accessToken,
      authState.shopId
    );

    const getUrl =
      `https://partner.shopeemobile.com${getPath}` +
      `?partner_id=${PARTNER_ID}` +
      `&timestamp=${getTimestamp}` +
      `&access_token=${authState.accessToken}` +
      `&shop_id=${authState.shopId}` +
      `&sign=${getSign}` +
      `&page_size=1` +
      `&comment_id=${COMMENT_ID_TESTE}`;

    const getResponse = await fetch(getUrl);
    const getData = await getResponse.json();

    if (getData.error) {
      return res.status(400).json({
        ok: false,
        etapa: "verificacao",
        shopee_error: getData
      });
    }

    const lista =
      getData.response?.item_comment_list || [];

    const avaliacao = lista.find(
      item =>
        String(item.comment_id) ===
        String(COMMENT_ID_TESTE)
    );

    if (!avaliacao) {
      return res.status(404).json({
        ok: false,
        message:
          "A avaliação de teste não foi encontrada."
      });
    }

    if (avaliacao.comment_reply) {
      return res.status(409).json({
        ok: false,
        message:
          "A avaliação já possui resposta. Nenhuma nova resposta foi enviada.",
        comment_id: COMMENT_ID_TESTE
      });
    }

    if (Number(avaliacao.rating_star) !== 5) {
      return res.status(400).json({
        ok: false,
        message:
          "A avaliação não possui mais 5 estrelas. Teste cancelado."
      });
    }

    // =====================================
    // 2. ENVIAR UMA ÚNICA RESPOSTA
    // =====================================

    const replyPath =
      "/api/v2/product/reply_comment";

    const replyTimestamp =
      Math.floor(Date.now() / 1000);

    const replySign = gerarAssinatura(
      replyPath,
      replyTimestamp,
      authState.accessToken,
      authState.shopId
    );

    const replyUrl =
      `https://partner.shopeemobile.com${replyPath}` +
      `?partner_id=${PARTNER_ID}` +
      `&timestamp=${replyTimestamp}` +
      `&access_token=${authState.accessToken}` +
      `&shop_id=${authState.shopId}` +
      `&sign=${replySign}`;

    const replyResponse = await fetch(replyUrl, {
      method: "POST",

      headers: {
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        comment_list: [
          {
            comment_id: COMMENT_ID_TESTE,
            comment: RESPOSTA_TESTE
          }
        ]
      })
    });

    const replyData =
      await replyResponse.json();

    if (replyData.error) {
      return res.status(400).json({
        ok: false,
        etapa: "envio",
        shopee_error: replyData
      });
    }

    return res.json({
      ok: true,

      message:
        "Resposta de teste enviada para a Shopee.",

      comment_id:
        COMMENT_ID_TESTE,

      buyer_username:
        avaliacao.buyer_username,

      rating_star:
        avaliacao.rating_star,

      resposta_enviada:
        RESPOSTA_TESTE,

      resposta_shopee:
        replyData
    });

  } catch (error) {
    console.error(
      "Erro test-reply-one:",
      error
    );

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/test-reply-batch-10", async (req, res) => {
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

    const getPath = "/api/v2/product/get_comment";

    const timestamp = Math.floor(Date.now() / 1000);

    const sign = gerarAssinatura(
      getPath,
      timestamp,
      authState.accessToken,
      authState.shopId
    );

    const url =
      `https://partner.shopeemobile.com${getPath}` +
      `?partner_id=${PARTNER_ID}` +
      `&timestamp=${timestamp}` +
      `&access_token=${authState.accessToken}` +
      `&shop_id=${authState.shopId}` +
      `&sign=${sign}` +
      `&page_size=100`;

    const response = await fetch(url);
    const data = await response.json();

    if (data.error) {
      return res.status(400).json({
        ok: false,
        etapa: "busca",
        shopee_error: data
      });
    }

    const lista =
      data.response?.item_comment_list || [];

    // =====================================
    // FILTRAR SOMENTE CANDIDATAS SEGURAS
    // =====================================

    const candidatas = lista
      .filter(avaliacao => {
        const semResposta =
          !avaliacao.comment_reply;

        const cincoEstrelas =
          Number(avaliacao.rating_star) === 5;

        const semComentario =
          !avaliacao.comment ||
          avaliacao.comment.trim() === "";

        return (
          semResposta &&
          cincoEstrelas &&
          semComentario
        );
      })
      .slice(0, 10);

    if (candidatas.length === 0) {
      return res.json({
        ok: true,
        message:
          "Nenhuma candidata encontrada para o lote de teste.",
        total_encontradas: 0
      });
    }

    const RESPOSTA_PADRAO =
      "Agradecemos muito pela sua avaliação! Ficamos felizes com sua compra e seguimos à disposição sempre que precisar.";

    // =====================================
    // ENVIAR RESPOSTAS
    // UMA POR UMA
    // =====================================

    const replyPath =
      "/api/v2/product/reply_comment";

    const resultados = [];

    for (const avaliacao of candidatas) {
      try {
        const replyTimestamp =
          Math.floor(Date.now() / 1000);

        const replySign = gerarAssinatura(
          replyPath,
          replyTimestamp,
          authState.accessToken,
          authState.shopId
        );

        const replyUrl =
          `https://partner.shopeemobile.com${replyPath}` +
          `?partner_id=${PARTNER_ID}` +
          `&timestamp=${replyTimestamp}` +
          `&access_token=${authState.accessToken}` +
          `&shop_id=${authState.shopId}` +
          `&sign=${replySign}`;

        const replyResponse = await fetch(replyUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            comment_list: [
              {
                comment_id:
                  avaliacao.comment_id,

                comment:
                  RESPOSTA_PADRAO
              }
            ]
          })
        });

        const replyData =
          await replyResponse.json();

        if (replyData.error) {
          resultados.push({
            comment_id:
              avaliacao.comment_id,

            buyer_username:
              avaliacao.buyer_username,

            sucesso: false,

            erro:
              replyData
          });
        } else {
          resultados.push({
            comment_id:
              avaliacao.comment_id,

            buyer_username:
              avaliacao.buyer_username,

            sucesso: true
          });
        }

      } catch (error) {
        resultados.push({
          comment_id:
            avaliacao.comment_id,

          buyer_username:
            avaliacao.buyer_username,

          sucesso: false,

          erro:
            error.message
        });
      }

      // pequena pausa entre respostas
      await new Promise(resolve =>
        setTimeout(resolve, 300)
      );
    }

    const enviadas =
      resultados.filter(
        resultado =>
          resultado.sucesso
      );

    const erros =
      resultados.filter(
        resultado =>
          !resultado.sucesso
      );

    return res.json({
      ok: true,

      message:
        "Lote de teste finalizado.",

      total_processado:
        resultados.length,

      enviadas:
        enviadas.length,

      erros:
        erros.length,

      resposta_utilizada:
        RESPOSTA_PADRAO,

      resultados
    });

  } catch (error) {
    console.error(
      "Erro test-reply-batch-10:",
      error
    );

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/db-test", async (req, res) => {
  try {
    const TEST_COMMENT_ID = 999999999999999;

    const { data: gravado, error: erroGravacao } =
      await supabase
        .from("reviews")
        .upsert(
          {
            comment_id: TEST_COMMENT_ID,
            shop_id: 757373207,
            item_id: 22497288394,
            item_status: "TEST",
            buyer_username: "TESTE_SUPABASE",
            rating_star: 5,
            comment: "Registro de teste do banco",
            shopee_create_time: Math.floor(Date.now() / 1000),
            status: "PENDENTE",
            updated_at: new Date().toISOString()
          },
          {
            onConflict: "comment_id"
          }
        )
        .select();

    if (erroGravacao) {
      return res.status(500).json({
        ok: false,
        etapa: "gravacao",
        erro: erroGravacao
      });
    }

    const { data: encontrado, error: erroLeitura } =
      await supabase
        .from("reviews")
        .select("*")
        .eq("comment_id", TEST_COMMENT_ID)
        .single();

    if (erroLeitura) {
      return res.status(500).json({
        ok: false,
        etapa: "leitura",
        erro: erroLeitura
      });
    }

    return res.json({
      ok: true,
      message: "Supabase conectado com sucesso.",
      gravado,
      encontrado
    });

  } catch (error) {
    console.error("Erro db-test:", error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/sync-reviews-test", async (req, res) => {
  try {
    // ==============================
    // 1. VALIDAR AUTORIZAÇÃO SHOPEE
    // ==============================

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

    // ==============================
    // 2. BUSCAR 100 AVALIAÇÕES
    // ==============================

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
      `&page_size=100`;

    const response = await fetch(url);
    const shopeeData = await response.json();

    if (shopeeData.error) {
      return res.status(400).json({
        ok: false,
        etapa: "shopee",
        shopee_error: shopeeData
      });
    }

    const avaliacoes =
      shopeeData.response?.item_comment_list || [];

    if (avaliacoes.length === 0) {
      return res.json({
        ok: true,
        message: "Nenhuma avaliação encontrada.",
        total_shopee: 0
      });
    }

    // ==============================
    // 3. DESCOBRIR O QUE JÁ EXISTE
    // ==============================

    const commentIds =
      avaliacoes.map(avaliacao =>
        Number(avaliacao.comment_id)
      );

    const {
      data: existentes,
      error: erroExistentes
    } = await supabase
      .from("reviews")
      .select("comment_id")
      .in("comment_id", commentIds);

    if (erroExistentes) {
      return res.status(500).json({
        ok: false,
        etapa: "consulta_banco",
        erro: erroExistentes
      });
    }

    const idsExistentes = new Set(
      (existentes || []).map(item =>
        String(item.comment_id)
      )
    );

    const totalNovas =
      avaliacoes.filter(
        avaliacao =>
          !idsExistentes.has(
            String(avaliacao.comment_id)
          )
      ).length;

    const totalJaExistiam =
      avaliacoes.length - totalNovas;

    // ==============================
    // 4. PREPARAR DADOS
    // ==============================

    const registros = avaliacoes.map(avaliacao => {
      const temResposta =
        Boolean(avaliacao.comment_reply);

      let replyText = null;
      let replyAt = null;

      if (temResposta) {
        replyText =
          avaliacao.comment_reply?.reply || null;

        const replyCreateTime =
          Number(
            avaliacao.comment_reply?.create_time
          );

        if (replyCreateTime) {
          replyAt =
            new Date(
              replyCreateTime * 1000
            ).toISOString();
        }
      }

      return {
        comment_id:
          Number(avaliacao.comment_id),

        shop_id:
          Number(authState.shopId),

        item_id:
          avaliacao.item_id
            ? Number(avaliacao.item_id)
            : null,

        buyer_username:
          avaliacao.buyer_username || null,

        rating_star:
          avaliacao.rating_star
            ? Number(avaliacao.rating_star)
            : null,

        comment:
          avaliacao.comment || "",

        shopee_create_time:
          avaliacao.create_time
            ? Number(avaliacao.create_time)
            : null,

        status:
          temResposta
            ? "RESPONDIDA"
            : "PENDENTE",

        reply_text:
          replyText,

        reply_at:
          replyAt,

        ultimo_erro:
          null,

        updated_at:
          new Date().toISOString()
      };
    });

    // ==============================
    // 5. UPSERT NO SUPABASE
    // ==============================

    const {
      data: gravadas,
      error: erroGravacao
    } = await supabase
      .from("reviews")
      .upsert(
        registros,
        {
          onConflict: "comment_id"
        }
      )
      .select(
        "comment_id,status,rating_star,buyer_username"
      );

    if (erroGravacao) {
      return res.status(500).json({
        ok: false,
        etapa: "gravacao_banco",
        erro: erroGravacao
      });
    }

    // ==============================
    // 6. RESUMO
    // ==============================

    const pendentes =
      registros.filter(
        item => item.status === "PENDENTE"
      ).length;

    const respondidas =
      registros.filter(
        item => item.status === "RESPONDIDA"
      ).length;

    return res.json({
      ok: true,

      message:
        "Sincronização de teste concluída.",

      total_recebido_shopee:
        avaliacoes.length,

      novas_no_banco:
        totalNovas,

      ja_existiam_no_banco:
        totalJaExistiam,

      total_upsert:
        gravadas?.length || 0,

      pendentes:
        pendentes,

      respondidas:
        respondidas,

      amostra:
        (gravadas || []).slice(0, 10)
    });

  } catch (error) {
    console.error(
      "Erro sync-reviews-test:",
      error
    );

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

async function salvarAvaliacoesNoSupabase(avaliacoes, itemStatus) {
  if (!avaliacoes || avaliacoes.length === 0) {
    return {
      gravadas: 0,
      pendentes: 0,
      respondidas: 0
    };
  }

  const registros = avaliacoes.map(avaliacao => {
    const temResposta =
      Boolean(avaliacao.comment_reply);

    let replyText = null;
    let replyAt = null;

    if (temResposta) {
      replyText =
        avaliacao.comment_reply?.reply || null;

      const replyCreateTime =
        Number(
          avaliacao.comment_reply?.create_time
        );

      if (replyCreateTime) {
        replyAt =
          new Date(
            replyCreateTime * 1000
          ).toISOString();
      }
    }

    return {
      comment_id:
        Number(avaliacao.comment_id),

      shop_id:
        Number(authState.shopId),

      item_id:
        avaliacao.item_id
          ? Number(avaliacao.item_id)
          : null,

      item_status:
        itemStatus || null,

      buyer_username:
        avaliacao.buyer_username || null,

      rating_star:
        avaliacao.rating_star
          ? Number(avaliacao.rating_star)
          : null,

      comment:
        avaliacao.comment || "",

      shopee_create_time:
        avaliacao.create_time
          ? Number(avaliacao.create_time)
          : null,

      status:
        temResposta
          ? "RESPONDIDA"
          : "PENDENTE",

      reply_text:
        replyText,

      reply_at:
        replyAt,

      ultimo_erro:
        null,

      updated_at:
        new Date().toISOString()
    };
  });

  const {
    data,
    error
  } = await supabase
    .from("reviews")
    .upsert(
      registros,
      {
        onConflict: "comment_id"
      }
    )
    .select("comment_id,status");

  if (error) {
    throw new Error(
      `Erro ao gravar avaliações no Supabase: ${error.message}`
    );
  }

  const pendentes =
    registros.filter(
      item => item.status === "PENDENTE"
    ).length;

  const respondidas =
    registros.filter(
      item => item.status === "RESPONDIDA"
    ).length;

  return {
    gravadas:
      data?.length || 0,

    pendentes,

    respondidas
  };
}

app.get("/full-db-sync-status", (req, res) => {
  let progresso = 0;

  if (fullDbSyncState.totalItens > 0) {
    progresso = (
      fullDbSyncState.itensProcessados /
      fullDbSyncState.totalItens *
      100
    ).toFixed(1);
  }

  return res.json({
    ok: true,

    running:
      fullDbSyncState.running,

    concluido:
      fullDbSyncState.concluido,

    progresso_percentual:
      Number(progresso),

    total_itens:
      fullDbSyncState.totalItens,

    itens_processados:
      fullDbSyncState.itensProcessados,

    total_avaliacoes_recebidas:
      fullDbSyncState.totalAvaliacoesRecebidas,

    total_gravadas:
      fullDbSyncState.totalGravadas,

    total_pendentes:
      fullDbSyncState.totalPendentes,

    total_respondidas:
      fullDbSyncState.totalRespondidas,

    erros:
      fullDbSyncState.erros.length,

    detalhes_erros:
      fullDbSyncState.erros.slice(0, 20),

    iniciado_em:
      fullDbSyncState.iniciadoEm,

    finalizado_em:
      fullDbSyncState.finalizadoEm
  });
});

app.get("/full-db-sync-start", (req, res) => {
  if (
    !authState.accessToken ||
    !authState.shopId
  ) {
    return res.status(401).json({
      ok: false,
      message:
        "Loja ainda não autorizada nesta execução."
    });
  }

  if (
    authState.expiresAt <= Date.now()
  ) {
    return res.status(401).json({
      ok: false,
      message:
        "Access token expirado."
    });
  }

  if (
    fullDbSyncState.running
  ) {
    return res.json({
      ok: true,
      message:
        "Sincronização completa já está em execução.",
      itens_processados:
        fullDbSyncState.itensProcessados,
      total_itens:
        fullDbSyncState.totalItens
    });
  }

  executarScanCompletoAvaliacoes();

  return res.json({
    ok: true,
    message:
      "Sincronização completa Shopee → Supabase iniciada.",
    status_url:
      "/full-db-sync-status"
  });
});

app.get("/db-review-status", async (req, res) => {
  try {
    const { count: total, error: erroTotal } =
      await supabase
        .from("reviews")
        .select("*", {
          count: "exact",
          head: true
        });

    if (erroTotal) {
      return res.status(500).json({
        ok: false,
        etapa: "total",
        erro: erroTotal
      });
    }

    const statusList = [
      "PENDENTE",
      "RESPONDIDA",
      "PROCESSANDO",
      "ERRO"
    ];

    const porStatus = {};

    for (const status of statusList) {
      const { count, error } =
        await supabase
          .from("reviews")
          .select("*", {
            count: "exact",
            head: true
          })
          .eq("status", status);

      if (error) {
        return res.status(500).json({
          ok: false,
          etapa: `status_${status}`,
          erro: error
        });
      }

      porStatus[status] = count || 0;
    }

    return res.json({
      ok: true,
      total_reviews_no_banco: total || 0,
      por_status: porStatus
    });

  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

async function obterOuCriarSyncJob(shopId) {
  const jobType = "FULL_REVIEW_SYNC";

  const {
    data: existente,
    error: erroConsulta
  } = await supabase
    .from("sync_jobs")
    .select("*")
    .eq("shop_id", shopId)
    .eq("job_type", jobType)
    .maybeSingle();

  if (erroConsulta) {
    throw new Error(
      `Erro ao consultar sync_jobs: ${erroConsulta.message}`
    );
  }

  if (existente) {
    return existente;
  }

  const {
    data: criado,
    error: erroCriacao
  } = await supabase
    .from("sync_jobs")
    .insert({
      shop_id: shopId,
      job_type: jobType,
      status: "PENDENTE",
      ultimo_indice_processado: -1
    })
    .select()
    .single();

  if (erroCriacao) {
    throw new Error(
      `Erro ao criar sync_job: ${erroCriacao.message}`
    );
  }

  return criado;
}

app.get("/sync-job-status", async (req, res) => {
  try {
    const shopId = Number(authState.shopId || 757373207);

    const {
      data,
      error
    } = await supabase
      .from("sync_jobs")
      .select("*")
      .eq("shop_id", shopId)
      .eq("job_type", "FULL_REVIEW_SYNC")
      .maybeSingle();

    if (error) {
      return res.status(500).json({
        ok: false,
        erro: error
      });
    }

    if (!data) {
      return res.json({
        ok: true,
        encontrado: false,
        message: "Nenhum checkpoint encontrado."
      });
    }

    return res.json({
      ok: true,
      encontrado: true,
      checkpoint: data
    });

  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/reply-batch-preview", async (req, res) => {
  try {
    const LIMITE = 20;

    const {
      data,
      error
    } = await supabase
      .from("reviews")
      .select(`
        id,
        comment_id,
        shop_id,
        item_id,
        buyer_username,
        rating_star,
        comment,
        status,
        tentativas,
        shopee_create_time
      `)
      .eq("shop_id", 757373207)
      .eq("status", "PENDENTE")
      .eq("rating_star", 5)
      .eq("comment", "")
      .neq("item_status", "TEST")
      .order("shopee_create_time", {
        ascending: false
      })
      .limit(LIMITE);

    if (error) {
      return res.status(500).json({
        ok: false,
        etapa: "consulta_supabase",
        erro: error
      });
    }

    return res.json({
      ok: true,

      ATENCAO:
        "Esta rota NÃO responde nenhuma avaliação.",

      limite:
        LIMITE,

      total_candidatas:
        data?.length || 0,

      candidatas:
        data || []
    });

  } catch (error) {
    console.error(
      "Erro reply-batch-preview:",
      error
    );

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.post("/reply-batch-run", async (req, res) => {
  try {

        const cronSecret =
      req.headers["x-cron-secret"];

    if (
      !process.env.REPLY_CRON_SECRET ||
      cronSecret !== process.env.REPLY_CRON_SECRET
    ) {
      return res.status(401).json({
        ok: false,
        message: "Não autorizado."
      });
    }

    if (replyEngineState.running) {
  return res.status(409).json({
    ok: false,
    message:
      "Já existe um lote de respostas em execução.",
    iniciado_em:
      replyEngineState.iniciadoEm
  });
}

replyEngineState.running = true;
replyEngineState.iniciadoEm =
  new Date().toISOString();

replyEngineState.finalizadoEm = null;
replyEngineState.ultimoResultado = null;

const recuperacao =
  await recuperarProcessamentosTravados();

console.log(
  "Recuperação de PROCESSANDO:",
  recuperacao
);

    // =====================================
    // CONFIGURAÇÃO DO LOTE
    // =====================================

    const SHOP_ID = 757373207;
    const LIMITE = 20;
    const LIMITE_DIARIO = 500;

    const RESPOSTA_PADRAO =
      "Agradecemos muito pela sua avaliação! Ficamos felizes com sua compra e seguimos à disposição sempre que precisar.";

    // =====================================
    // 1. VALIDAR SHOPEE
    // =====================================

    if (!authState.shopId || !authState.refreshToken) {
  replyEngineState.running = false;

  return res.status(401).json({
    ok: false,
    message:
      "Autenticação Shopee não disponível."
  });
}

if (Number(authState.shopId) !== SHOP_ID) {
  replyEngineState.running = false;

  return res.status(400).json({
    ok: false,
    message:
      "A loja autorizada não corresponde à Key Quality."
  });
}

// Verifica o token e renova automaticamente
// se estiver próximo da expiração.
try {
  const resultadoToken =
    await renovarTokenShopeeSeNecessario();

  console.log(
    "Verificação de token Shopee:",
    resultadoToken
  );

} catch (erroToken) {
  replyEngineState.running = false;

  return res.status(401).json({
    ok: false,
    message:
      "Não foi possível renovar a autenticação Shopee.",
    erro:
      erroToken.message
  });
}

// Proteção adicional:
// só continua se houver access token válido.
if (
  !authState.accessToken ||
  !authState.expiresAt ||
  authState.expiresAt <= Date.now()
) {
  replyEngineState.running = false;

  return res.status(401).json({
    ok: false,
    message:
      "Access token Shopee indisponível ou expirado após tentativa de renovação."
  });
}

    const respondidasHoje =
  await contarRespostasHoje(SHOP_ID);

const restanteHoje =
  LIMITE_DIARIO - respondidasHoje;

if (restanteHoje <= 0) {
  replyEngineState.running = false;

  return res.status(429).json({
    ok: false,
    message:
      "Limite diário de respostas atingido.",

    limite_diario:
      LIMITE_DIARIO,

    respondidas_hoje:
      respondidasHoje,

    restante_hoje:
      0
  });
}

    // =====================================
    // 2. BUSCAR CANDIDATAS NO SUPABASE
    // =====================================

    const {
      data: candidatas,
      error: erroConsulta
    } = await supabase
      .from("reviews")
      .select(`
        id,
        comment_id,
        buyer_username,
        rating_star,
        comment,
        status,
        tentativas
      `)
      .eq("shop_id", SHOP_ID)
      .eq("status", "PENDENTE")
      .eq("rating_star", 5)
      .eq("comment", "")
      .neq("item_status", "TEST")
      .order("shopee_create_time", {
        ascending: false
      })
     .limit(
  Math.min(
    LIMITE,
    restanteHoje
  )
);

   if (erroConsulta) {
  replyEngineState.running = false;

  replyEngineState.finalizadoEm =
    new Date().toISOString();

  return res.status(500).json({
    ok: false,
    etapa: "consulta_supabase",
    erro: erroConsulta
  });
}

   if (!candidatas || candidatas.length === 0) {
  replyEngineState.running = false;

  replyEngineState.finalizadoEm =
    new Date().toISOString();

  replyEngineState.ultimoResultado = {
    total_processado: 0,
    enviadas: 0,
    erros: 0,
    ignoradas: 0
  };

  return res.json({
    ok: true,
    message:
      "Nenhuma avaliação elegível encontrada.",
    total_processado: 0
  });
}

    const resultados = [];

    const replyPath =
      "/api/v2/product/reply_comment";

    // =====================================
    // 3. PROCESSAR UMA POR UMA
    // =====================================

    for (const avaliacao of candidatas) {
      try {
        // ---------------------------------
        // TRAVA: PENDENTE → PROCESSANDO
        // ---------------------------------

        const {
          data: bloqueada,
          error: erroBloqueio
        } = await supabase
          .from("reviews")
          .update({
            status: "PROCESSANDO",
            updated_at:
              new Date().toISOString()
          })
          .eq("id", avaliacao.id)
          .eq("status", "PENDENTE")
          .select("id,comment_id")
          .maybeSingle();

        if (erroBloqueio) {
          throw new Error(
            `Erro ao bloquear avaliação: ${erroBloqueio.message}`
          );
        }

        // Outra execução já pegou esse registro.
        if (!bloqueada) {
          resultados.push({
            comment_id:
              avaliacao.comment_id,
            sucesso: false,
            ignorada: true,
            motivo:
              "Avaliação não estava mais PENDENTE."
          });

          continue;
        }

        // ---------------------------------
        // ENVIAR PARA SHOPEE
        // ---------------------------------

        const timestamp =
          Math.floor(Date.now() / 1000);

        const sign = gerarAssinatura(
          replyPath,
          timestamp,
          authState.accessToken,
          authState.shopId
        );

        const replyUrl =
          `https://partner.shopeemobile.com${replyPath}` +
          `?partner_id=${PARTNER_ID}` +
          `&timestamp=${timestamp}` +
          `&access_token=${authState.accessToken}` +
          `&shop_id=${authState.shopId}` +
          `&sign=${sign}`;

        const replyResponse =
          await fetch(replyUrl, {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json"
            },

            body: JSON.stringify({
              comment_list: [
                {
                  comment_id:
                    Number(
                      avaliacao.comment_id
                    ),

                  comment:
                    RESPOSTA_PADRAO
                }
              ]
            })
          });

        const replyData =
          await replyResponse.json();

        // ---------------------------------
        // ERRO SHOPEE
        // ---------------------------------

        if (replyData.error) {
          const erroTexto =
            JSON.stringify(replyData);

          await supabase
            .from("reviews")
            .update({
              status: "ERRO",

              tentativas:
                Number(
                  avaliacao.tentativas || 0
                ) + 1,

              ultimo_erro:
                erroTexto,

              updated_at:
                new Date().toISOString()
            })
            .eq("id", avaliacao.id);

          resultados.push({
            comment_id:
              avaliacao.comment_id,

            buyer_username:
              avaliacao.buyer_username,

            sucesso: false,

            erro:
              replyData
          });

          continue;
        }

        // ---------------------------------
        // SUCESSO
        // ---------------------------------

        await supabase
          .from("reviews")
          .update({
            status: "RESPONDIDA",

            reply_text:
              RESPOSTA_PADRAO,

            reply_at:
              new Date().toISOString(),

            tentativas:
              Number(
                avaliacao.tentativas || 0
              ) + 1,

            ultimo_erro:
              null,

            updated_at:
              new Date().toISOString()
          })
          .eq("id", avaliacao.id);

        resultados.push({
          comment_id:
            avaliacao.comment_id,

          buyer_username:
            avaliacao.buyer_username,

          sucesso: true
        });

      } catch (error) {
        // ---------------------------------
        // ERRO INTERNO
        // ---------------------------------

        try {
          await supabase
            .from("reviews")
            .update({
              status: "ERRO",

              tentativas:
                Number(
                  avaliacao.tentativas || 0
                ) + 1,

              ultimo_erro:
                error.message,

              updated_at:
                new Date().toISOString()
            })
            .eq("id", avaliacao.id);

        } catch (erroBanco) {
          console.error(
            "Erro adicional ao registrar falha:",
            erroBanco
          );
        }

        resultados.push({
          comment_id:
            avaliacao.comment_id,

          buyer_username:
            avaliacao.buyer_username,

          sucesso: false,

          erro:
            error.message
        });
      }

      // Pequena pausa entre respostas
      await new Promise(resolve =>
        setTimeout(resolve, 300)
      );
    }

    // =====================================
    // 4. RESULTADO FINAL
    // =====================================

    const enviadas =
      resultados.filter(
        item => item.sucesso === true
      );

    const erros =
      resultados.filter(
        item =>
          item.sucesso === false &&
          !item.ignorada
      );

    const ignoradas =
      resultados.filter(
        item => item.ignorada === true
      );

      replyEngineState.running = false;

replyEngineState.finalizadoEm =
  new Date().toISOString();

replyEngineState.ultimoResultado = {
  total_processado:
    resultados.length,

  enviadas:
    enviadas.length,

  erros:
    erros.length,

  ignoradas:
    ignoradas.length
};

    return res.json({
      ok: true,

      message:
        "Lote operacional finalizado.",

      limite:
        LIMITE,

      total_processado:
        resultados.length,

      enviadas:
        enviadas.length,

      erros:
        erros.length,

      ignoradas:
        ignoradas.length,

      resposta_utilizada:
        RESPOSTA_PADRAO,

      resultados
    });

  } catch (error) {
    console.error(
      "Erro reply-batch-run:",
      error
    );

    replyEngineState.running = false;

replyEngineState.finalizadoEm =
  new Date().toISOString();

replyEngineState.ultimoResultado = {
  erro: error.message
};

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

async function consultarComentarioShopeePorId(commentId) {
  const SHOP_ID = 757373207;

  await renovarTokenShopeeSeNecessario();

  const path =
    "/api/v2/product/get_comment";

  const timestamp =
    Math.floor(Date.now() / 1000);

  const sign =
    gerarAssinatura(
      path,
      timestamp,
      authState.accessToken,
      SHOP_ID
    );

  const url =
    `https://partner.shopeemobile.com${path}` +
    `?partner_id=${PARTNER_ID}` +
    `&timestamp=${timestamp}` +
    `&access_token=${authState.accessToken}` +
    `&shop_id=${SHOP_ID}` +
    `&sign=${sign}` +
    `&comment_id=${Number(commentId)}` +
    `&page_size=10`;

  const response =
    await fetch(url);

  const data =
    await response.json();

  if (data.error) {
    throw new Error(
      `Erro Shopee ao consultar comment_id ${commentId}: ${JSON.stringify(data)}`
    );
  }

  const comentarios =
    data?.response?.item_comment_list || [];

  return comentarios.find(
    item =>
      Number(item.comment_id) ===
      Number(commentId)
  ) || null;
}

async function recuperarProcessamentosTravados() {
  const SHOP_ID = 757373207;

  const limite =
    new Date(
      Date.now() - 10 * 60 * 1000
    ).toISOString();

  const {
    data: travados,
    error: erroConsulta
  } = await supabase
    .from("reviews")
    .select(`
      id,
      comment_id,
      tentativas,
      updated_at
    `)
    .eq("shop_id", SHOP_ID)
    .eq("status", "PROCESSANDO")
    .lt("updated_at", limite);

  if (erroConsulta) {
    throw new Error(
      `Erro ao consultar PROCESSANDO travados: ${erroConsulta.message}`
    );
  }

  if (!travados || travados.length === 0) {
    return {
      encontrados: 0,
      confirmados_respondidos: 0,
      devolvidos_pendente: 0,
      falhas_verificacao: 0
    };
  }

  let confirmadosRespondidos = 0;
  let devolvidosPendente = 0;
  let falhasVerificacao = 0;

  for (const registro of travados) {
    try {

      const comentario =
        await consultarComentarioShopeePorId(
          registro.comment_id
        );

      // =====================================
      // SHOPEE CONFIRMA QUE JÁ TEM RESPOSTA
      // =====================================

      const respostaShopee =
        comentario?.comment_reply?.reply;

      if (
        typeof respostaShopee === "string" &&
        respostaShopee.trim() !== ""
      ) {

        const replyCreateTime =
          comentario?.comment_reply?.create_time;

        const replyAt =
          replyCreateTime
            ? new Date(
                Number(replyCreateTime) * 1000
              ).toISOString()
            : new Date().toISOString();

        const {
          error: erroAtualizacao
        } = await supabase
          .from("reviews")
          .update({
            status: "RESPONDIDA",

            reply_text:
              respostaShopee,

            reply_at:
              replyAt,

            ultimo_erro:
              null,

            updated_at:
              new Date().toISOString()
          })
          .eq("id", registro.id);

        if (erroAtualizacao) {
          throw new Error(
            `Erro ao confirmar RESPONDIDA no Supabase: ${erroAtualizacao.message}`
          );
        }

        confirmadosRespondidos++;

        console.log(
          `Recuperação segura: comment_id ${registro.comment_id} já estava respondido na Shopee.`
        );

        continue;
      }

      // =====================================
      // SHOPEE CONFIRMA QUE NÃO HÁ RESPOSTA
      // =====================================

      if (comentario) {

        const {
          error: erroAtualizacao
        } = await supabase
          .from("reviews")
          .update({
            status: "PENDENTE",

            ultimo_erro:
              "Processamento anterior foi interrompido. Shopee consultada e nenhuma resposta foi encontrada. Registro devolvido para PENDENTE.",

            updated_at:
              new Date().toISOString()
          })
          .eq("id", registro.id);

        if (erroAtualizacao) {
          throw new Error(
            `Erro ao devolver registro para PENDENTE: ${erroAtualizacao.message}`
          );
        }

        devolvidosPendente++;

        continue;
      }

      // =====================================
      // COMENTÁRIO NÃO LOCALIZADO
      // NÃO DEVOLVE PARA PENDENTE
      // =====================================

      falhasVerificacao++;

      await supabase
        .from("reviews")
        .update({
          ultimo_erro:
            "Recuperação automática não conseguiu localizar o comentário na Shopee. Mantido em PROCESSANDO para evitar resposta duplicada.",

          updated_at:
            new Date().toISOString()
        })
        .eq("id", registro.id);

    } catch (error) {

      falhasVerificacao++;

      console.error(
        `Erro ao reconciliar comment_id ${registro.comment_id}:`,
        error
      );

      // Em caso de dúvida, NÃO reenviar.
      // Mantemos PROCESSANDO para evitar duplicidade.
      await supabase
        .from("reviews")
        .update({
          ultimo_erro:
            `Falha na verificação antes da recuperação: ${error.message}`,

          updated_at:
            new Date().toISOString()
        })
        .eq("id", registro.id);
    }

    await new Promise(resolve =>
      setTimeout(resolve, 200)
    );
  }

  return {
    encontrados:
      travados.length,

    confirmados_respondidos:
      confirmadosRespondidos,

    devolvidos_pendente:
      devolvidosPendente,

    falhas_verificacao:
      falhasVerificacao
  };
}

app.get("/processing-status", async (req, res) => {
  try {
    const SHOP_ID = 757373207;

    const {
      data,
      error
    } = await supabase
      .from("reviews")
      .select(`
        id,
        comment_id,
        buyer_username,
        status,
        tentativas,
        updated_at
      `)
      .eq("shop_id", SHOP_ID)
      .eq("status", "PROCESSANDO")
      .order("updated_at", {
        ascending: true
      });

    if (error) {
      return res.status(500).json({
        ok: false,
        etapa: "consulta_supabase",
        erro: error
      });
    }

    return res.json({
      ok: true,
      total_processando:
        data?.length || 0,
      registros:
        data || []
    });

  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/recover-processing-test", async (req, res) => {
  try {
    const resultado =
      await recuperarProcessamentosTravados();

    return res.json({
      ok: true,
      resultado
    });

  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/reply-engine-status", (req, res) => {
  return res.json({
    ok: true,

    running:
      replyEngineState.running,

    iniciado_em:
      replyEngineState.iniciadoEm,

    finalizado_em:
      replyEngineState.finalizadoEm,

    ultimo_resultado:
      replyEngineState.ultimoResultado
  });
});

app.get("/reply-daily-status", async (req, res) => {
  try {
    const SHOP_ID = 757373207;
    const LIMITE_DIARIO = 500;

    const respondidasHoje =
      await contarRespostasHoje(SHOP_ID);

    const restanteHoje =
      Math.max(
        0,
        LIMITE_DIARIO - respondidasHoje
      );

    return res.json({
      ok: true,
      shop_id: SHOP_ID,
      limite_diario: LIMITE_DIARIO,
      respondidas_hoje: respondidasHoje,
      restante_hoje: restanteHoje
    });

  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/reply-retry-preview", async (req, res) => {
  try {
    const SHOP_ID = 757373207;
    const LIMITE = 20;
    const MAX_TENTATIVAS = 3;

    const {
      data,
      error
    } = await supabase
      .from("reviews")
      .select(`
        id,
        comment_id,
        item_id,
        item_status,
        buyer_username,
        rating_star,
        comment,
        status,
        tentativas,
        ultimo_erro,
        updated_at
      `)
      .eq("shop_id", SHOP_ID)
      .eq("status", "ERRO")
      .lt("tentativas", MAX_TENTATIVAS)
      .neq("item_status", "TEST")
      .order("updated_at", {
        ascending: true
      })
      .limit(LIMITE);

    if (error) {
      return res.status(500).json({
        ok: false,
        etapa: "consulta_supabase",
        erro: error
      });
    }

    return res.json({
      ok: true,

      ATENCAO:
        "Esta rota NÃO reprocessa nenhuma avaliação.",

      max_tentativas:
        MAX_TENTATIVAS,

      limite:
        LIMITE,

      elegiveis_retry:
        data?.length || 0,

      registros:
        data || []
    });

  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/auth/refresh-test", async (req, res) => {
  try {
    const resultado =
      await renovarTokenShopeeSeNecessario();

    return res.json({
      ok: true,
      resultado,
      token_valid:
        authState.expiresAt > Date.now()
    });

  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.post("/auth/refresh-force-test", async (req, res) => {
  try {
    const resultado =
      await renovarTokenShopeeSeNecessario(true);

    return res.json({
      ok: true,
      resultado,
      token_valid:
        authState.expiresAt > Date.now()
    });

  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/comment-reply-diagnostic/:commentId", async (req, res) => {
  try {
    const SHOP_ID = 757373207;

    await renovarTokenShopeeSeNecessario();

    const commentId =
      Number(req.params.commentId);

    if (!commentId) {
      return res.status(400).json({
        ok: false,
        message: "comment_id inválido."
      });
    }

    const path =
      "/api/v2/product/get_comment";

    const timestamp =
      Math.floor(Date.now() / 1000);

    const sign =
      gerarAssinatura(
        path,
        timestamp,
        authState.accessToken,
        SHOP_ID
      );

    const url =
      `https://partner.shopeemobile.com${path}` +
      `?partner_id=${PARTNER_ID}` +
      `&timestamp=${timestamp}` +
      `&access_token=${authState.accessToken}` +
      `&shop_id=${SHOP_ID}` +
      `&sign=${sign}` +
      `&comment_id=${commentId}` +
      `&page_size=10`;

    const response =
      await fetch(url);

    const data =
      await response.json();

    return res.json({
      ok: !data.error,
      comment_id_consultado: commentId,
      shopee: data
    });

  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/wake", (req, res) => {
  return res.status(200).send("OK");
});

app.listen(PORT, async () => {
  console.log(
    `Servidor rodando na porta ${PORT}`
  );

  try {
    await carregarAuthStateDoSupabase();
  } catch (error) {
    console.error(
      "Erro ao restaurar autenticação Shopee:",
      error
    );
  }
});