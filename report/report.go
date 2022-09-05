package report


import(
	"github.com/EasyRecon/wappaGo/structure"
"os"
"strconv"
)



func header()(string){
	a := `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>WappGo report</title>
    <link rel="canonical" href="https://getbootstrap.com/docs/4.0/examples/navbar-fixed/">
    <!-- Bootstrap core CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Custom styles for this template -->

  </head>
  <body>
  <style>
  body {
  min-height: 75rem;
  padding-top: 6.5rem;
}
main{
	padding:20px
}
.badge-info {
    margin-right: 5px;
    border: 1px solid #3498db;
    box-shadow: inset 0px 0px 15px -9px #2980b9;
    color: #2c3e50;
}
.badge-success {
    margin-right: 5px;
    border: 1px solid #2ecc71;
    box-shadow: inset 0px 0px 15px -9px #27ae60;
    color: #16a085;
}
.badge-warning {
    margin-right: 5px;
    border: 1px solid #f39c12;
    box-shadow: inset 0px 0px 15px -9px #e67e22;
    color: #d35400;
}
.badge-danger {
    margin-right: 5px;
    border: 1px solid #e74c3c;
    box-shadow: inset 0px 0px 15px -9px #c0392b;
    color: #c0392b;
}
  </style>
   <style type="text/css">
    footer {
      border-top: 1px solid rgba(0, 0, 0, .125);
      margin-top: 50px;
      padding: 50px;
      text-align: center;
      font-size: 12px;
      color: rgb(68, 68, 68);
    }
   
    #screenshotModal .page-screenshot {
      width: 100%;
      cursor: pointer;
    }
  </style>
    <nav class="navbar navbar-expand-md navbar-dark fixed-top bg-dark">
      <a class="navbar-brand" href="#">WappaGo Report</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarCollapse" aria-controls="navbarCollapse" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <!--<div class="collapse navbar-collapse" id="navbarCollapse">
        <form class="form-inline mt-2 mt-md-0">
          <input class="form-control mr-sm-2" type="text" placeholder="Search" aria-label="Search">
          <button class="btn btn-outline-success my-2 my-sm-0" type="submit">Search</button>
        </form>
      </div>-->
    </nav>
    <main role="main" class="row">`
    return a
}

func card(data structure.Data,screenPath string)(string){
	var technos string
	var version string
	var status string
	for _,techno := range data.Infos.Technologies {
		version =""
		if techno.Version != "" {
			version=" | "+techno.Version
		}
		technos = technos+"<span class=\"badge badge-pill text-break text-wrap badge-info\">"+techno.Name+version+"</span>"
	}
	status ="badge-secondary"
	switch i := data.Infos.Status_code; {
	    case i<300:
	        status ="badge-success"
	    case i>299 && i<400:
	        status ="badge-info"
	    case i>399 && i<500:
	        status ="badge-warning"
        case i>499:
        	status ="badge-danger"
    }
		return `<div class="card page-card col-2" style="margin:2px;padding:0px">
            <div title="`+data.Infos.Title+`" class="card-header text-truncate"> `+data.Url+` </div>
            <div class="page-screenshot-container">
              <img src="`+screenPath+`/`+data.Infos.Screenshot+`" alt="`+data.Infos.Title+`" onerror="this.src='https://upload.wikimedia.org/wikipedia/commons/thumb/a/ac/No_image_available.svg/1024px-No_image_available.svg.png'" class="card-img page-screenshot" style="transform: scale(1); transform-origin: 11.5772% 95.4698%;">
            </div>
            <div class="card-body">
              <h5 class="card-title">`+data.Infos.Title+`</h5>
              <p class="card-text">
                <span class="badge badge-pill text-break text-wrap `+status+`">Status: `+strconv.Itoa(data.Infos.Status_code)+`</span>
                `+technos+`
              </p>
            </div>
            <div class="card-footer">
              <a href="`+data.Url+`" target="_blank" class="btn btn-outline-secondary btn-sm card-link float-right">Visit Page</a>
            </div>
          </div>`

}


func Report_main(datas []structure.Data, screenPath string){
	var cards string
	for _,data:= range datas {
		cards = cards + card(data,screenPath)
	}
		file, _ := os.OpenFile(
				"wappaGo_report.html",
				os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
				0666,
			)
			file.WriteString(header()+cards+footer())
			file.Close()

}
func footer()(string){
	a := `   </main>
	 <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/2.9.2/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/js/bootstrap.min.js"></script>
  </body>
</html>`
return a
}
   
