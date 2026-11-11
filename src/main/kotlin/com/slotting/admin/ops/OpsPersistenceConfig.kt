package com.slotting.admin.ops

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import javax.sql.DataSource

@Configuration
class OpsPersistenceConfig {
    @Bean
    fun opsNoticeRepository(dataSource: DataSource): OpsNoticeRepository = JdbcOpsNoticeRepository(dataSource)

    @Bean
    fun opsDecisionRepository(dataSource: DataSource): JdbcOpsDecisionRepository = JdbcOpsDecisionRepository(dataSource)
}
