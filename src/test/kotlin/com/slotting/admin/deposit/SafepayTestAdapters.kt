package com.slotting.admin.deposit

import com.slotting.admin.provider.port.ProviderHttpClient
import com.slotting.admin.provider.port.adapters.SafepayRaastAdapter
import com.slotting.admin.provider.port.httpResponse
import java.util.UUID

fun deterministicSafepayAdapter(): SafepayRaastAdapter = SafepayRaastAdapter(
    ProviderHttpClient { _ ->
        httpResponse(200, """{"tracker":"tracker-${UUID.randomUUID()}"}""")
    },
)
