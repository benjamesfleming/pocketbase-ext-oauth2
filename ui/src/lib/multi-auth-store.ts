import { BaseAuthStore, type AuthRecord } from "pocketbase";

export type AuthCacheItem = {
    token: string;
    iat: number;
    record: AuthRecord;
};

export default class MultiAuthStore extends BaseAuthStore {
    private index: number = -1;
    private items: AuthCacheItem[] = [];
    private storageKey: string;

    constructor(storageKey = "pocketbase_auth") {
        super();

        this.storageKey = storageKey;
        this.items = this._storageGet(this.storageKey) || [];

        this.removeExpiredTokens();
    }

    get selected(): AuthCacheItem | null {
        if (this.index < 0 || this.index >= this.items.length) {
            return null;
        }
        return this.items[this.index] || null;
    }

    get count(): number {
        return this.records.length;
    }

    get records(): AuthCacheItem[] {
        return this.items;
    }

    select(index: number): AuthCacheItem | null {
        this.index = index;
        return this.selected;
    }

    selectByRecord(record: AuthRecord): AuthCacheItem | null {
        const index = this.findIndex(record);
        if (index >= 0) {
            return this.select(index);
        }
        return null;
    }

    findIndex(record: AuthRecord): number {
        return this.items.findIndex(item => this.key(item.record) === this.key(record));
    }

    /**
     * @inheritdoc
     */
    get token(): string {
        return this.selected?.token || "";
    }

    /**
     * @inheritdoc
     */
    get record(): AuthRecord {
        return this.selected?.record || null;
    }

    /**
     * @deprecated use `record` instead.
     */
    get model(): AuthRecord {
        return this.record;
    }

    /**
     * @inheritdoc
     */
    save(token: string, record?: AuthRecord) {
        this.items.push({ token, iat: Math.floor(Date.now() / 1000), record: record || null });
        this.index = this.items.length - 1;

        this._storageSet(this.storageKey, this.items);

        super.save(token, record);
    }

    /**
     * @inheritdoc
     */
    clear() {
        this._storageRemove(this.storageKey);

        super.clear();
    }

    //

    private removeExpiredTokens() {
        let newItems = [];
        let newIndex = this.index;

        let latestValidIssuedAt: Record<string, number> = {};
        for (const item of this.items) {
            if ((latestValidIssuedAt[this.key(item.record)] || 0) < item.iat) {
                latestValidIssuedAt[this.key(item.record)] = item.iat;
            }
        }

        for (let i = 0; i < this.items.length; i++) {
            this.index = i;
            if (this.isValid && latestValidIssuedAt[this.key(this.items[i]!.record)] === this.items[i]!.iat) {
                newItems.push(this.items[i]);
            } else {
                if (i < newIndex) {
                    newIndex--; // shift external index left
                }
                if (i === newIndex) {
                    newIndex = -1; // or clamp to next item if you prefer
                }
            }
        }

        this.items = newItems;
        this.index = newIndex;

        this._storageSet(this.storageKey, this.items);

        if (this.selected) {
            super.save(this.selected.token, this.selected.record);
        } else {
            super.clear();
        }
    }

    private key(record: AuthRecord): string {
        return record!.collectionId + record!.id;
    }

    // ---------------------------------------------------------------
    // Internal helpers:
    // ---------------------------------------------------------------

    /**
     * Retrieves `key` from the browser's local storage
     * (or runtime/memory if local storage is undefined).
     */
    private _storageGet(key: string): any {
        const rawValue = window.localStorage.getItem(key) || "";
        try {
            return JSON.parse(rawValue);
        } catch (e) {
            return rawValue;
        }
    }

    /**
     * Stores a new data in the browser's local storage
     * (or runtime/memory if local storage is undefined).
     */
    private _storageSet(key: string, value: any) {
        let normalizedVal = value;
        if (typeof value !== "string") {
            normalizedVal = JSON.stringify(value);
        }
        window.localStorage.setItem(key, normalizedVal);
    }

    /**
     * Removes `key` from the browser's local storage and the runtime/memory.
     */
    private _storageRemove(key: string) {
        window.localStorage?.removeItem(key);
    }
}