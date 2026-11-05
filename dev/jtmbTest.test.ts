import { afterEach, expect, it, mock, spyOn } from "bun:test";
import { getCommonCheckpoint, getRealmRpcUrls, selectOrdinaryAccounts, validateNamespace } from "./jtmbTest";

it("includes the third validator even when legacy rpc_url lists only two", () => {
    expect(getRealmRpcUrls({ id: 0, rpc_url: ["http://127.0.0.1:13380", "http://127.0.0.1:13381"],
        validators: [{ edge_nodes: [{}] }, { edge_nodes: [{}] }, { edge_nodes: [{}] }] })).toEqual([
        "http://127.0.0.1:13380/", "http://127.0.0.1:13381/", "http://127.0.0.1:13382/",
    ]);
});

afterEach(() => mock.restore());

it("excludes all validators and the reserved relayer from noncontiguous Strategy5 users", () => {
    const validators = [0, 262144, 786432, 1048576, 1572864, 1310720];
    const realms = new Map([[0, ["http://127.0.0.1:13380"]], [1, ["http://127.0.0.1:13390"]]]);
    const accounts = selectOrdinaryAccounts(17, 10, validators, realms);
    expect(accounts).toHaveLength(10);
    expect(new Set(accounts.map(account => account.uid)).size).toBe(10);
    expect(accounts.every(account => !validators.includes(account.uid) && account.uid !== 524288)).toBe(true);
    expect(selectOrdinaryAccounts(27, 20, validators, realms)).toHaveLength(20);
    expect(() => selectOrdinaryAccounts(17, 11, validators, realms)).toThrow("ordinary accounts available");
});

it("refuses production or conflicting namespace bindings", () => {
    expect(() => validateNamespace("production", "")).toThrow();
    expect(() => validateNamespace("jtmb-new", "jtmb-old")).toThrow();
    expect(() => validateNamespace("jtmb-test", "jtmb-test")).not.toThrow();
});

it("compares every replica at the same minimum checkpoint", async () => {
    const queried: number[] = [];
    spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
        const body = JSON.parse(String(init?.body));
        if (body.method === "psy_get_latest_checkpoint_id") return Response.json({ result: String(url).endsWith("a") ? 10 : 11 });
        queried.push(body.params[0]);
        return Response.json({ result: { user_tree_root: "same" } });
    });
    expect(await getCommonCheckpoint(["http://localhost/a", "http://localhost/b"])).toBe(10);
    expect(queried).toEqual([10, 10]);
});

it("rejects divergent replica state instead of reporting success", async () => {
    spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
        const body = JSON.parse(String(init?.body));
        return Response.json({ result: body.method === "psy_get_latest_checkpoint_id" ? 10 : { user_tree_root: String(url) } });
    });
    await expect(getCommonCheckpoint(["http://localhost/a", "http://localhost/b"])).rejects.toThrow("State roots differ");
});
