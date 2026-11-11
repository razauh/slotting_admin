package com.slotting.admin.rails

class NoVerifiedDepositException :
    RuntimeException("a verified deposit is required before placing bets")
