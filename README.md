# CFX Telemetry & Forensics

> Framework de segurança defensiva para monitoramento cinemático em tempo real
> e análise forense de memória volátil no ecossistema FiveM / FXServer.
>
> **Autor:** Breno, Eric®

---

## Índice

- [Apresentação](#apresentação)
- [1. Telemetria de Rede](#1-telemetria-de-rede--análise-cinemática)
- [2. Profiling de Input](#2-profiling-de-input--curva-de-reação-biológica)
- [3. Análise Forense de Memória](#3-análise-forense-de-memória-volátil)
- [4. Conclusão](#4-conclusão)

---

## Apresentação

Este repositório documenta a metodologia de análise defensiva **não-intrusiva** adotada para identificação de clientes manipulados (cheats) no ecossistema FiveM/FXServer.

A abordagem é integralmente **Black-Box**: nenhum dado privado de terceiros é coletado ou interceptado. A validação de integridade é feita exclusivamente sobre dados sincronizados publicamente pela rede ou sobre dumps de memória obtidos com consentimento explícito do operador do servidor.

**Escopo técnico:**
- Análise de pacotes de sincronização de entidades (posição, velocidade)
- Profiling estatístico de padrões de input
- Inspeção forense de regiões de memória volátil via assinaturas YARA

---

## 1. Telemetria de Rede — Análise Cinemática

Cheats como **Speedhack**, **Noclip** e **Blink Teleport** alteram os vetores de posição reportados pelo cliente. Como esses dados são transmitidos via pacotes UDP de sincronização de entidades — e são, por natureza, públicos para todos os peers da sessão — é possível isolar anomalias analisando exclusivamente o deslocamento físico das entidades no espaço tridimensional ao longo do tempo.

### Modelo de Validação de Movimento

O detector opera sobre três etapas sequenciais:

**1. Cálculo de deslocamento euclidiano**
```
Δd = √( (x₂-x₁)² + (y₂-y₁)² + (z₂-z₁)² )
```

**2. Velocidade média no intervalo**
```
v = Δd / Δt
```

**3. Regra de detecção**
```
Se v > (limite_contextual + margem_jitter) → Anomalia registrada
```

> [!WARNING]
> O `limite_contextual` é dinâmico: o sistema aplica um limiar reduzido para entidades a pé e um limiar ampliado para entidades dentro de veículos. A `margem_jitter` absorve oscilações normais de latência de rede.

### Implementação — C\#

```csharp
using System;
using System.Collections.Generic;

public class Vector3
{
    public float X { get; set; }
    public float Y { get; set; }
    public float Z { get; set; }

    public static float Distance(Vector3 a, Vector3 b)
    {
        return (float)Math.Sqrt(
            Math.Pow(b.X - a.X, 2) +
            Math.Pow(b.Y - a.Y, 2) +
            Math.Pow(b.Z - a.Z, 2)
        );
    }
}

public class EntityState
{
    public Vector3 Position    { get; set; } = new();
    public long    Timestamp   { get; set; }
    public bool    IsInVehicle { get; set; }
}

public class TelemetryValidator
{
    private readonly Dictionary<int, EntityState> _history = new();

    // Limites empíricos baseados nos valores máximos do motor GTA V
    private const float MaxFootSpeedMs    = 12.0f;   // ~43 km/h (sprint máximo)
    private const float MaxVehicleSpeedMs = 130.0f;  // ~468 km/h (teto de veículos)
    private const float JitterBuffer      = 5.0f;    // compensação de oscilação de ping

    public void ProcessNetworkInboundPayload(int netId, Vector3 currentPos, bool inVehicle)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        if (_history.TryGetValue(netId, out EntityState? last))
        {
            float dt           = (now - last.Timestamp) / 1000.0f;
            if (dt <= 0f) return;

            float displacement = Vector3.Distance(currentPos, last.Position);
            float speedLimit   = last.IsInVehicle ? MaxVehicleSpeedMs : MaxFootSpeedMs;
            float maxAllowed   = (speedLimit * dt) + JitterBuffer;

            if (displacement > maxAllowed)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(
                    $"[ANOMALIA] netId={netId} | " +
                    $"deslocamento={displacement:F2}m | " +
                    $"intervalo={dt:F3}s | " +
                    $"limite={maxAllowed:F2}m"
                );
                Console.ResetColor();
            }
        }

        _history[netId] = new EntityState
        {
            Position    = currentPos,
            Timestamp   = now,
            IsInVehicle = inVehicle
        };
    }
}
```

---

## 2. Profiling de Input — Curva de Reação Biológica

Ferramentas de auxílio de mira (Aimbots, Triggerbots, Silent Aimbots) modificam ângulos de visão ou interceptam eventos de mouse diretamente na memória de execução. A detecção passiva se baseia em três propriedades mensuráveis do comportamento humano:

| Propriedade | Comportamento Humano | Comportamento Automatizado |
|---|---|---|
| **Latência de reação** | 150 ms – 250 ms (limiar fisiológico) | < 16 ms (um frame) ou instantâneo |
| **Trajetória angular** | Curva irregular com micro-acelerações e ruído de fadiga muscular | Interpolação linear ou curva de Bézier perfeita sem ruído |
| **Consistência temporal** | Variância natural entre tentativas (±30–60 ms) | Variância próxima de zero — repetição determinística |

> A ausência de ruído natural na trajetória de mira é o indicador mais robusto. Nenhum humano produz curvas matematicamente perfeitas de forma consistente — qualquer suavização artificial elimina a variância esperada por fadiga e micro-tremores musculares.

---

## 3. Análise Forense de Memória Volátil

Clientes maliciosos modernos operam via **injeção direta em memória RAM** e ocultam sua presença apagando entradas de módulo na PEB (*Process Environment Block*), tornando-se invisíveis a enumerações convencionais de processos.

A abordagem forense consiste em inspecionar **dumps de memória** (`.dmp`) obtidos com consentimento do operador, buscando artefatos residuais por assinatura estrutural — independente de nomes de arquivo ou entradas de processo.

### Regras YARA — Assinatura Heurística

```yara
rule CFX_Memory_Forensics_Audit
{
    meta:
        description = "Detecção de hooks nativos e executores LUA em memória volátil"
        author      = "Segurança Defensiva — CFX"
        confidence  = "Alta"

    strings:
        // Hooks em chamadas nativas internas do CitizenFX
        $hook_1 = "TriggerServerEventInternal"       ascii wide
        $hook_2 = "citizen::script::handler"          ascii wide
        $hook_3 = "rage::scrThread::GetThreadPointer" ascii wide

        // Assinaturas de executores e interpretadores LUA externos
        $lua_1  = "loadstring(game:HttpGet"           ascii wide
        $lua_2  = "RunString"                         ascii wide
        $lua_3  = "Cscript_executor"                  ascii wide

        // Chamadas nativas frequentemente abusadas via VMT hijacking
        $vmt_1  = "SetSuperJumpThisTurn"              ascii
        $vmt_2  = "GiveWeaponToPed"                   ascii
        $vmt_3  = "SetEntityInvincible"               ascii

    condition:
        // $vmt_* só dispara se os TRÊS padrões coexistirem — uso isolado é legítimo em scripts normais
        (2 of ($hook_*)) or
        (any of ($lua_*)) or
        (all of ($vmt_*))
}
```

> [!NOTE]
> **VMT Integrity** — O motor de física do GTA V mantém tabelas de ponteiros virtuais (VMTs) para cada classe de entidade (veículos, pedestres). Qualquer redirecionamento de ponteiro — como substituir a função de processamento de dano por um endereço arbitrário — produz um desvio mensurável em relação ao endereço base do módulo legítimo. Essa divergência é detectável sem necessidade de acesso ao código-fonte do cliente.

---

## 4. Conclusão

Soluções de anticheat baseadas exclusivamente em varredura de disco são superficiais e facilmente contornadas por qualquer implementação que opere em memória sem persistência em arquivo.

A robustez real vem da combinação de três camadas complementares:

1. **Física aplicada** — leis de movimento detectam o impossível independente da implementação do cheat
2. **Estatística comportamental** — padrões de input revelam automação onde olhos humanos não conseguem distinguir
3. **Forense estrutural** — assinaturas em memória expõem artefatos que não existem em execuções limpas

Nenhuma dessas camadas depende de heurísticas proprietárias ou acesso privilegiado além do que o próprio servidor já recebe por protocolo.

---

<sub>Metodologia de segurança defensiva — uso restrito ao ambiente operacional autorizado.</sub>
