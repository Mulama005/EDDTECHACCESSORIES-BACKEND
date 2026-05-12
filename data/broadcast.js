const [broadcast, setBroadcast] = useState({
  subject: "",
  preheader: "",
  campaign_type: "promotion", // promotion | announcement | newsletter

  product_name: "",
  product_description: "",
  product_price: "",
  product_image: "",
  product_link: "",

  cta_text: "Buy Now",

  audience: "all", // all | active | inactive
});