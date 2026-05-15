export default function About() {
  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">À propos</h1>
        <p className="mt-2 text-zinc-400">Présentation du projet SecretHunter Android.</p>
      </div>

      <section className="rounded-3xl border border-zinc-800 bg-[#1f1f1f] p-6">
        <h2 className="text-xl font-semibold text-white">Objectif du projet</h2>
        <p className="mt-3 leading-7 text-zinc-400">
          SecretHunter Android est un outil académique d’analyse statique Android. Il permet d’identifier les secrets codés en dur,
          les tokens exposés, les URLs sensibles et les configurations réseau faibles.
        </p>
      </section>

      <section className="rounded-3xl border border-zinc-800 bg-[#1f1f1f] p-6">
        <h2 className="text-xl font-semibold text-white">Différence avec MobSF</h2>
        <p className="mt-3 leading-7 text-zinc-400">
          SecretHunter Android n’a pas pour objectif de remplacer MobSF. Il s’agit d’un outil spécialisé dans la détection des secrets,
          tokens et endpoints exposés dans les applications Android.
        </p>
      </section>

      <section className="rounded-3xl border border-zinc-800 bg-[#1f1f1f] p-6">
        <h2 className="text-xl font-semibold text-white">Rôle de l’IA</h2>
        <p className="mt-3 leading-7 text-zinc-400">
          L’IA est utilisée comme une couche d’aide à la décision afin de classifier les risques, expliquer les vulnérabilités et proposer
          des recommandations adaptées.
        </p>
      </section>
    </div>
  );
}
