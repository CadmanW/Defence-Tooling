rules=$(git status -s | grep rules | rev | cut -d'/' -f1 | rev | cut -d'.' -f1)
for rule in $rules; do
  cargo bench -p flying-ace-engine --bench engine "$rule"
done
