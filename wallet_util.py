from eth_account import Account


def create_wallet() -> list[str]:
    Account.enable_unaudited_hdwallet_features()
    account, mnemonic = Account.create_with_mnemonic()
    return [str(account.address), str(account.key.hex()), str(mnemonic)]
