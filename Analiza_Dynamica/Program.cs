using System.Net.Http.Json;
using System.Text.Json;
using System.Text;

namespace Analiza_Dynamica;

internal class Program
{
    private static async Task<int> Main(string[] args)
    {
   
        var baseUrl = GetArg(args, "--url") ?? "http://localhost:5048";
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri))
        {
            Console.WriteLine($"[E] URL invalid: {baseUrl}");
            return 3;
        }

        Console.WriteLine("==== Analiza dinamica API ====");
        Console.WriteLine($"Tinta: {baseUri}");

        using var http = new HttpClient();
        http.BaseAddress = baseUri;
        http.Timeout = TimeSpan.FromSeconds(30);
        var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);

 
        var descrieri = new Dictionary<string, string>
        {
            ["GET /healthz"] = "verifica starea aplicatiei",
            ["GET /api/posts?take=5"] = "listeaza postari cu limitare",
            ["POST /api/posts (creare)"] = "creeaza o postare",
            ["GET /api/posts/{id}"] = "citeste postare dupa id",
            ["PUT /api/posts/{id} (actualizare)"] = "actualizeaza postarea",
            ["Verificare actualizare titlu"] = "verifica campul Title dupa actualizare",
            ["POST /api/posts/{id}/comments (creare)"] = "adauga comentariu la postare",
            ["GET /api/posts/{id}/comments"] = "listeaza comentariile postarii",
            ["POST /api/posts (invalid -> 400)"] = "validare create: campuri lipsa => 400",
            ["DELETE /api/comments/{id}"] = "sterge comentariu",
            ["DELETE /api/posts/{id}"] = "sterge postare",
            ["GET /api/posts/{id} (dupa stergere -> 404)"] = "verifica 404 dupa stergere",
            ["GET /api/posts/999999 (404)"] = "id inexistent returneaza 404",
            ["GET /api/posts/999999/comments (404)"] = "comentarii pt post inexistent => 404",
            ["PUT /api/posts/0 (404)"] = "actualizare pe id inexistent => 404",
            ["POST /api/posts/0/comments (404)"] = "comentariu pe id inexistent => 404",
            ["HEAD /api/posts"] = "raspuns la HEAD (200 sau 405)",
            ["POST /api/posts (text/plain -> 415)"] = "content-type invalid la creare (acceptat 415 sau 400)",
            ["Filtru published (creare nepublicat si verificare)"] = "filtru IsPublished true/false",
            ["Cautare q"] = "cautare in titlu/continut",
            ["Paginare (take mare, skip negativ)"] = "limiteaza take si normalizeaza skip",
            ["Unicode/emoji in titlu"] = "suport unicode in titlu",
            ["Comentariu lung (1000 caractere)"] = "limita lungime comentariu",
            ["XSS payload stocare/lectura"] = "stocare si citire text brut",
            ["Dublu delete (404 a doua oara)"] = "idempotenta la stergere"
        };

        var rezultate = new List<(string Nume, bool Ok, string? Eroare)>();
        int total = 0, ok = 0, fail = 0;
        async Task Test(string nume, Func<Task> act)
        {
            total++;
            try
            {
                await act();
                ok++;
                rezultate.Add((nume, true, null));
                Console.WriteLine($"[OK] {nume}");
            }
            catch (Exception ex)
            {
                fail++;
                rezultate.Add((nume, false, ex.Message));
                Console.WriteLine($"[FAIL] {nume} -> {ex.Message}");
            }
        }

        // Helperi locali
        async Task<JsonElement> SafeJson(HttpResponseMessage r)
        {
            var stream = await r.Content.ReadAsStreamAsync();
            return await JsonSerializer.DeserializeAsync<JsonElement>(stream, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        }
        void EnsureSuccess(HttpResponseMessage r)
        {
            if (!r.IsSuccessStatusCode) throw new($"Cod neasteptat: {(int)r.StatusCode}");
        }
        void EnsureStatus(HttpResponseMessage r, int expected)
        {
            var code = (int)r.StatusCode;
            if (code != expected) throw new($"Cod neasteptat: {code} (asteptat {expected})");
        }
        async Task<JsonElement[]> GetArray(string path)
            => await http.GetFromJsonAsync<JsonElement[]>(path) ?? Array.Empty<JsonElement>();
        static bool ContainsId(JsonElement[] arr, int id)
        {
            foreach (var el in arr)
            {
                if (el.TryGetProperty("id", out var v) && v.GetInt32() == id) return true;
            }
            return false;
        }
        static void Require(bool cond, string msg)
        {
            if (!cond) throw new(msg);
        }

        int postId = 0;
        int commentId = 0;

        // 1) healthz
        await Test("GET /healthz", async () =>
        {
            var r = await http.GetAsync("/healthz");
            EnsureStatus(r, 200);
        });

        // 2) lista postari
        await Test("GET /api/posts?take=5", async () =>
        {
            var r = await http.GetAsync("/api/posts?take=5");
            EnsureSuccess(r);
        });

        // 3) creare postare
        await Test("POST /api/posts (creare)", async () =>
        {
            var create = new { title = "Analiza Dyn Post", content = "<p>Continut</p>", isPublished = true };
            var r = await http.PostAsJsonAsync("/api/posts", create, json);
            EnsureStatus(r, 201);
            var body = await SafeJson(r);
            postId = body.TryGetProperty("id", out var idEl) ? idEl.GetInt32() : 0;
            if (postId <= 0) throw new("Raspuns fara id creat");
        });

        // 4) citire postare
        await Test("GET /api/posts/{id}", async () =>
        {
            Require(postId > 0, "postId invalid");
            var r = await http.GetAsync($"/api/posts/{postId}");
            EnsureSuccess(r);
        });

        // 5) actualizare postare
        await Test("PUT /api/posts/{id} (actualizare)", async () =>
        {
            Require(postId > 0, "postId invalid");
            var upd = new { title = "Analiza Dyn Post (upd)", content = "<p>Upd</p>", isPublished = true };
            var r = await http.PutAsJsonAsync($"/api/posts/{postId}", upd, json);
            EnsureStatus(r, 204);
        });

        // 6) verificare actualizare titlu
        await Test("Verificare actualizare titlu", async () =>
        {
            Require(postId > 0, "postId invalid");
            var doc = await http.GetFromJsonAsync<JsonElement>($"/api/posts/{postId}");
            if (!doc.TryGetProperty("title", out var t) || t.GetString() != "Analiza Dyn Post (upd)")
                throw new("Titlul nu a fost actualizat corect");
        });

        // 7) creare comentariu
        await Test("POST /api/posts/{id}/comments (creare)", async () =>
        {
            Require(postId > 0, "postId invalid");
            var c = new { author = "Dyn", content = "Bravo" };
            var r = await http.PostAsJsonAsync($"/api/posts/{postId}/comments", c, json);
            EnsureStatus(r, 201);
            var body = await SafeJson(r);
            commentId = body.TryGetProperty("id", out var idEl) ? idEl.GetInt32() : 0;
            if (commentId <= 0) throw new("Raspuns fara id comentariu");
        });

        // 8) lista comentarii
        await Test("GET /api/posts/{id}/comments", async () =>
        {
            Require(postId > 0, "postId invalid");
            var r = await http.GetAsync($"/api/posts/{postId}/comments");
            EnsureSuccess(r);
        });

        // 9) negativ create invalid
        await Test("POST /api/posts (invalid -> 400)", async () =>
        {
            var bad = new { title = "Rau", content = "", isPublished = true };
            var r = await http.PostAsJsonAsync("/api/posts", bad, json);
            EnsureStatus(r, 400);
        });

        // 10) delete comentariu
        await Test("DELETE /api/comments/{id}", async () =>
        {
            if (commentId > 0)
            {
                var r = await http.DeleteAsync($"/api/comments/{commentId}");
                EnsureStatus(r, 204);
            }
        });

        // 11) delete postare
        await Test("DELETE /api/posts/{id}", async () =>
        {
            if (postId > 0)
            {
                var r = await http.DeleteAsync($"/api/posts/{postId}");
                EnsureStatus(r, 204);
            }
        });

        // 12) 404 dupa stergere
        await Test("GET /api/posts/{id} (dupa stergere -> 404)", async () =>
        {
            if (postId > 0)
            {
                var r = await http.GetAsync($"/api/posts/{postId}");
                EnsureStatus(r, 404);
            }
        });

        // 13) GET inexistent
        await Test("GET /api/posts/999999 (404)", async () =>
        {
            var r = await http.GetAsync("/api/posts/999999");
            EnsureStatus(r, 404);
        });

        // 14) comentarii pe inexistent
        await Test("GET /api/posts/999999/comments (404)", async () =>
        {
            var r = await http.GetAsync("/api/posts/999999/comments");
            EnsureStatus(r, 404);
        });

        // 15) PUT pe inexistent
        await Test("PUT /api/posts/0 (404)", async () =>
        {
            var upd = new { title = "X", content = "Y", isPublished = true };
            var r = await http.PutAsJsonAsync("/api/posts/0", upd, json);
            EnsureStatus(r, 404);
        });

        // 16) POST comentariu pe inexistent
        await Test("POST /api/posts/0/comments (404)", async () =>
        {
            var c = new { author = "A", content = "B" };
            var r = await http.PostAsJsonAsync("/api/posts/0/comments", c, json);
            EnsureStatus(r, 404);
        });

        // 17) HEAD /api/posts (200 sau 405)
        await Test("HEAD /api/posts", async () =>
        {
            var req = new HttpRequestMessage(HttpMethod.Head, "/api/posts");
            var r = await http.SendAsync(req);
            var code = (int)r.StatusCode;
            if (code != 200 && code != 405) throw new($"Cod neasteptat: {code}");
        });

        // 18) content-type invalid (acceptam 415 sau 400)
        await Test("POST /api/posts (text/plain -> 415)", async () =>
        {
            var payload = new StringContent("{\"title\":\"t\",\"content\":\"c\"}", Encoding.UTF8, "text/plain");
            var r = await http.PostAsync("/api/posts", payload);
            var code = (int)r.StatusCode;
            if (code != 415 && code != 400) throw new($"Cod neasteptat: {code} (asteptat 415 sau 400)");
        });

        // 19) Filtru published
        await Test("Filtru published (creare nepublicat si verificare)", async () =>
        {
            var create = new { title = "Nepublicat", content = "C", isPublished = false };
            var r = await http.PostAsJsonAsync("/api/posts", create, json);
            EnsureStatus(r, 201);
            var body = await SafeJson(r);
            var pid = body.GetProperty("id").GetInt32();

            var arrTrue = await GetArray("/api/posts?published=true&take=50");
            if (ContainsId(arrTrue, pid)) throw new("Element nepublicat prezent in published=true");

            var arrFalse = await GetArray("/api/posts?published=false&take=50");
            if (!ContainsId(arrFalse, pid)) throw new("Element nepublicat lipsa in published=false");

            var del = await http.DeleteAsync($"/api/posts/{pid}");
            EnsureStatus(del, 204);
        });

        // 20) Cautare q
        await Test("Cautare q", async () =>
        {
            var token = $"tok-{Guid.NewGuid():N}";
            var create = new { title = $"Titlu {token}", content = "Z", isPublished = true };
            var r = await http.PostAsJsonAsync("/api/posts", create, json);
            EnsureStatus(r, 201);
            var body = await SafeJson(r);
            var pid = body.GetProperty("id").GetInt32();

            var arr = await GetArray($"/api/posts?q={token}&take=50");
            if (!ContainsId(arr, pid)) throw new("Postul creat nu a fost gasit de cautare");

            var del = await http.DeleteAsync($"/api/posts/{pid}");
            EnsureStatus(del, 204);
        });

        // 21) Paginare
        await Test("Paginare (take mare, skip negativ)", async () =>
        {
            var r1 = await http.GetAsync("/api/posts?take=1000");
            EnsureSuccess(r1);
            var r2 = await http.GetAsync("/api/posts?skip=-5&take=5");
            EnsureSuccess(r2);
        });

        // 22) Unicode in titlu
        await Test("Unicode/emoji in titlu", async () =>
        {
            var title = "Test unicode 😃";
            var create = new { title, content = "CU", isPublished = true };
            var r = await http.PostAsJsonAsync("/api/posts", create, json);
            EnsureStatus(r, 201);
            var body = await SafeJson(r);
            var pid = body.GetProperty("id").GetInt32();

            var doc = await http.GetFromJsonAsync<JsonElement>($"/api/posts/{pid}");
            if (!doc.TryGetProperty("title", out var t) || t.GetString() != title)
                throw new("Titlul Unicode nu se potriveste");

            var del = await http.DeleteAsync($"/api/posts/{pid}");
            EnsureStatus(del, 204);
        });

        // 23) Comentariu lung
        await Test("Comentariu lung (1000 caractere)", async () =>
        {
            var create = new { title = "PentruComentLung", content = "C", isPublished = true };
            var r = await http.PostAsJsonAsync("/api/posts", create, json);
            EnsureStatus(r, 201);
            var pid = (await SafeJson(r)).GetProperty("id").GetInt32();

            var big = new string('a', 1000);
            var com = new { author = "A", content = big };
            var rc = await http.PostAsJsonAsync($"/api/posts/{pid}/comments", com, json);
            EnsureStatus(rc, 201);
            var cid = (await SafeJson(rc)).GetProperty("id").GetInt32();

            var dc = await http.DeleteAsync($"/api/comments/{cid}");
            EnsureStatus(dc, 204);
            var dp = await http.DeleteAsync($"/api/posts/{pid}");
            EnsureStatus(dp, 204);
        });

        // 24) XSS payload stocat/citit
        await Test("XSS payload stocare/lectura", async () =>
        {
            var create = new { title = "XSS Test", content = "C", isPublished = true };
            var r = await http.PostAsJsonAsync("/api/posts", create, json);
            EnsureStatus(r, 201);
            var pid = (await SafeJson(r)).GetProperty("id").GetInt32();

            var payload = "<img src=x onerror=alert(1)>";
            var com = new { author = "H", content = payload };
            var rc = await http.PostAsJsonAsync($"/api/posts/{pid}/comments", com, json);
            EnsureStatus(rc, 201);

            var list = await GetArray($"/api/posts/{pid}/comments");
            bool found = false;
            foreach (var el in list)
            {
                if (el.TryGetProperty("content", out var c) && c.GetString() == payload) { found = true; break; }
            }
            if (!found) throw new("Payload XSS nu a fost regasit");

            var dp = await http.DeleteAsync($"/api/posts/{pid}");
            EnsureStatus(dp, 204);
        });

        // 25) Dublu delete
        await Test("Dublu delete (404 a doua oara)", async () =>
        {
            // facem post temporar
            var r = await http.PostAsJsonAsync("/api/posts", new { title = "tmp", content = "c", isPublished = true }, json);
            EnsureStatus(r, 201);
            var pid = (await SafeJson(r)).GetProperty("id").GetInt32();
            var d1 = await http.DeleteAsync($"/api/posts/{pid}");
            EnsureStatus(d1, 204);
            var d2 = await http.DeleteAsync($"/api/posts/{pid}");
            EnsureStatus(d2, 404);
        });

        Console.WriteLine("\n==== Rezumat ====");
        Console.WriteLine($"Total: {total}, Reusite: {ok}, Esecuri: {fail}");
        Console.WriteLine(fail == 0 ? "Rezultat: SUCCES" : "Rezultat: CU PROBLEME");
        Console.WriteLine("\nDetalii teste:");
        foreach (var r in rezultate)
        {
            var desc = descrieri.TryGetValue(r.Nume, out var d) ? d : "-";
            if (r.Ok)
                Console.WriteLine($"- [OK] {r.Nume} — {desc}");
            else
                Console.WriteLine($"- [FAIL] {r.Nume} — {desc} | Eroare: {r.Eroare}");
        }

        return fail == 0 ? 0 : 2;
    }

    private static string? GetArg(string[] args, string key)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (string.Equals(args[i], key, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        return null;
    }
}
