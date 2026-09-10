export type Money=Readonly<{amountMinor:bigint;currency:string}>;
export function money(amountMinor:bigint,currency:string):Money{const normalized=currency.toUpperCase();if(amountMinor<BigInt(0))throw new Error("MONEY_AMOUNT_INVALID");if(!/^[A-Z]{3}$/.test(normalized))throw new Error("CURRENCY_INVALID");return{amountMinor,currency:normalized}}
export function invoiceTotal(subtotalMinor:bigint,taxMinor:bigint|null){return subtotalMinor+(taxMinor??BigInt(0))}
